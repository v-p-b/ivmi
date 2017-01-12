#include <cstdio>
#include <string>
#include <iostream>
#include <fstream>
#include <libdrakvuf/libdrakvuf.h>
#include <unistd.h>
#include <glib.h>
#include <json-c/json.h>
#include <zmqpp/zmqpp.hpp>
#include "ivmi.h"

using namespace std;

ivmi_t ivmi_ctx;

json_object* handle_error(int32_t e){
    json_object* resp=json_object_new_object();
    json_object* errcode=json_object_new_int(e);
    json_object_object_add(resp, "error", errcode);
    json_object_put(errcode);
    return resp;
}

json_object* handle_pause()
{
    if (ivmi_ctx.drakvuf){
        drakvuf_pause(ivmi_ctx.drakvuf);
    }else{
        return handle_error(1);
    }
    return json_object_new_string("OK");
}

json_object* handle_resume()
{
    if (ivmi_ctx.drakvuf){
        drakvuf_resume(ivmi_ctx.drakvuf);
    }else{
        return handle_error(1);
    }
    return json_object_new_string("OK");
}

void* handle_mem_read()
{
    return NULL;
}

void* handle_mem_write()
{
    return NULL;
}

void* handle_reg_read()
{
    return NULL;
}

void* handle_reg_write()
{
    return NULL;
}

void* handle_trap_add()
{
    return NULL;
}

void* handle_trap_del()
{
    return NULL;
}

void* handle_proc_attach()
{
    return NULL;
}

json_object* handle_vm_list(){
    // TODO Calling the OS shell until I figure out the interface to Xen...
    char buffer[128];
    std::string result = "";
    std::shared_ptr<FILE> pipe(popen("xl list", "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer, 128, pipe.get()) != NULL)
            result += buffer;
    }

    return json_object_new_string(result.c_str());
    
}

json_object* handle_info(){
    json_object* ret = json_object_new_object();
    
    os_t os_type = drakvuf_get_os_type(ivmi_ctx.drakvuf);
    addr_t kernel_base = drakvuf_get_kernel_base(ivmi_ctx.drakvuf);
    addr_t curr_proc = drakvuf_get_current_process(ivmi_ctx.drakvuf, 0); // TODO multi-CPU
    addr_t curr_thread = drakvuf_get_current_thread(ivmi_ctx.drakvuf, 0);
    char* process_name = drakvuf_get_process_name(ivmi_ctx.drakvuf, curr_proc);
    vmi_pid_t process_pid;
    drakvuf_get_process_pid(ivmi_ctx.drakvuf, curr_proc, &process_pid);

    json_object_object_add(ret,"os",json_object_new_int64(os_type));
    json_object_object_add(ret,"kernel_base",json_object_new_int64(kernel_base));
    json_object_object_add(ret,"current_process",json_object_new_int64(curr_proc));
    json_object_object_add(ret,"current_thread",json_object_new_int64(curr_thread));
    if (curr_proc && process_name){
        json_object_object_add(ret,"process_name",json_object_new_string(process_name));
        json_object_object_add(ret,"process_pid",json_object_new_int64(process_pid));
    }

    free(process_name);
    return ret;
}

json_object* handle_init(json_object* json_pkt){
    json_object* json_domain;
    json_object* json_profile;

    ivmi_ctx.domid=0;
    ivmi_ctx.process.pid=0;
    ivmi_ctx.process.cr3=0;

    if (!json_object_object_get_ex(json_pkt, "domain", &json_domain)){
        return handle_error(1);
    }
    if (!json_object_object_get_ex(json_pkt, "profile", &json_profile)){
        return handle_error(2);
    }

    ofstream tmpf;
    string tmpn = tmpnam(NULL); // insecure
    tmpf.open(tmpn); // TODO delete this after use!
    cout << "Writing profile... " << tmpn << endl;
    tmpf << json_object_to_json_string(json_profile);
    tmpf.close();
    cout << "Profile ready." << endl;
    char *domain=strdup(json_object_get_string(json_domain));

    if (!drakvuf_init(&ivmi_ctx.drakvuf, domain, tmpn.c_str(), false)){
        free(domain);
        return handle_error(3);
    }    

    ivmi_ctx.drakvuf_loop = g_thread_new("drakvuf_loop", (GThreadFunc)drakvuf_loop, ivmi_ctx.drakvuf);
    // TODO free JSON objects!
    free(domain);
    drakvuf_pause(ivmi_ctx.drakvuf);
    return handle_info();
} 

json_object* handle_close(){
    if (ivmi_ctx.drakvuf){
        drakvuf_interrupt(ivmi_ctx.drakvuf,9);
        g_thread_join(ivmi_ctx.drakvuf_loop);
        drakvuf_close(ivmi_ctx.drakvuf, false);
        ivmi_ctx.domid=0;
        ivmi_ctx.process.pid=0;
        ivmi_ctx.process.cr3=0;
        ivmi_ctx.drakvuf=NULL;
    } 
    return json_object_new_string("OK");
}

json_object* handle_find_process(json_object* json_pkt){
    json_object* pid_json;
    json_object_object_get_ex(json_pkt, "pid", &pid_json); 

    addr_t eprocess_addr;
    int64_t pid=json_object_get_int64(pid_json);
    cout << pid << endl;
    drakvuf_find_eprocess(ivmi_ctx.drakvuf, pid, 0, &eprocess_addr);

    json_object_put(pid_json);

    return json_object_new_int64(eprocess_addr);
}

json_object* handle_process_list(){
    json_object *ret = json_object_new_array();

    // From libvmi/examples/process-list.c
    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(ivmi_ctx.drakvuf);

    addr_t list_head = 0, next_list_entry = 0;
    addr_t current_process = 0;
    char *procname = NULL;
    vmi_pid_t pid = 0;
    unsigned long tasks_offset = 0, pid_offset = 0, name_offset = 0;
    status_t status;

   try{ 
        if (!vmi){
            throw 1;
        }

        /* init the offset values */
        if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
            tasks_offset = vmi_get_offset(vmi, "linux_tasks");
            name_offset = vmi_get_offset(vmi, "linux_name");
            pid_offset = vmi_get_offset(vmi, "linux_pid");
        }
        else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
            tasks_offset = vmi_get_offset(vmi, "win_tasks");
            name_offset = vmi_get_offset(vmi, "win_pname");
            pid_offset = vmi_get_offset(vmi, "win_pid");
        }

        if (0 == tasks_offset) {
            printf("Failed to find win_tasks\n");
            throw 0x10;
        }
        if (0 == pid_offset) {
            printf("Failed to find win_pid\n");
            throw 0x11;
        }
        if (0 == name_offset) {
            printf("Failed to find win_pname\n");
            throw 0x12;
        }

        drakvuf_pause(ivmi_ctx.drakvuf);

        /* get the head of the list */
        if (VMI_OS_LINUX == drakvuf_get_os_type(ivmi_ctx.drakvuf)) {
            /* Begin at PID 0, the 'swapper' task. It's not typically shown by OS
             *  utilities, but it is indeed part of the task list and useful to
             *  display as such.
             */
            list_head = vmi_translate_ksym2v(vmi, "init_task") + tasks_offset;
        }
        else if (VMI_OS_WINDOWS == drakvuf_get_os_type(ivmi_ctx.drakvuf)) {

            // find PEPROCESS PsInitialSystemProcess
            if(VMI_FAILURE == vmi_read_addr_ksym(vmi, "PsActiveProcessHead", &list_head)) {
                printf("Failed to find PsActiveProcessHead\n");
                throw 0x30;
            }
        }

        next_list_entry = list_head;

        /* walk the task list */
        do {
            json_object* proc_elem = json_object_new_object();
            current_process = next_list_entry - tasks_offset;

            /* Note: the task_struct that we are looking at has a lot of
             * information.  However, the process name and id are burried
             * nice and deep.  Instead of doing something sane like mapping
             * this data to a task_struct, I'm just jumping to the location
             * with the info that I want.  This helps to make the example
             * code cleaner, if not more fragile.  In a real app, you'd
             * want to do this a little more robust :-)  See
             * include/linux/sched.h for mode details */

            /* NOTE: _EPROCESS.UniqueProcessId is a really VOID*, but is never > 32 bits,
             * so this is safe enough for x64 Windows for example purposes */
            vmi_read_32_va(vmi, current_process + pid_offset, 0, (uint32_t*)&pid);

            procname = vmi_read_str_va(vmi, current_process + name_offset, 0);

            if (!procname) {
                printf("Failed to find procname\n");
                throw 0x40;
            }

            /* print out the process name */
            //printf("[%5d] %s (struct addr:%"PRIx64")\n", pid, procname, current_process);
            json_object_object_add(proc_elem, "pid", json_object_new_int64(pid));
            json_object_object_add(proc_elem, "process_name", json_object_new_string(procname));
            json_object_object_add(proc_elem, "eprocess", json_object_new_int64(current_process));
            json_object_array_add(ret, proc_elem);
            if (procname) {
                free(procname);
                procname = NULL;
            }

            /* follow the next pointer */

            status = vmi_read_addr_va(vmi, next_list_entry, 0, &next_list_entry);
            if (status == VMI_FAILURE) {
                printf("Failed to read next pointer in loop at %"PRIx64"\n", next_list_entry);
                throw 0x50;
            }

        } while(next_list_entry != list_head);
        drakvuf_resume(ivmi_ctx.drakvuf);
        drakvuf_release_vmi(ivmi_ctx.drakvuf);
        return ret;
    }catch(int ex){
        return handle_error(ex);
    }
}

json_object* handle_command(json_object *json_pkt){
    json_object* json_cmd = NULL;
    try{
        if (!json_object_object_get_ex(json_pkt, "cmd",&json_cmd)){
            fprintf(stderr,"Invalid packet!\n");
            throw -1;     
        }

        int32_t cmd=json_object_get_int(json_cmd);
        printf("Got command: %d\n",cmd);
        json_object* json_resp;
        switch(cmd){
            case CMD_LIST:
                json_resp=handle_vm_list();
                break;
            case CMD_INIT:
                json_resp=handle_init(json_pkt);
                break;
            case CMD_PAUSE:
                json_resp=handle_pause();
                break;
            case CMD_RESUME:
                json_resp=handle_resume();
                break;
            case CMD_MEM_R:
                json_resp=handle_error(-1);
                break;
            case CMD_MEM_W:
                json_resp=handle_error(-1);
                break;
            case CMD_REG_R:
                json_resp=handle_error(-1);
                break;
            case CMD_REG_W:
                json_resp=handle_error(-1);
                break;
            case CMD_TRAP_ADD:
                json_resp=handle_error(-1);
                break;
            case CMD_TRAP_DEL:
                json_resp=handle_error(-1);
                break;
            case CMD_INFO:
                json_resp=handle_info();
                break;
            case CMD_PROC_LIST:
                json_resp=handle_process_list();
                break;
            case CMD_FIND_PROC:
                json_resp=handle_find_process(json_pkt);
                break;
            case CMD_CLOSE:
                json_resp=handle_close();
                break;
            default:
                json_resp=handle_error(-1);
        }
        
        json_object_put(json_cmd);

        return json_resp;
    }catch (int ex){ 
        json_object_put(json_cmd);
        return json_tokener_parse("{\"error\":-2}");
    }
}

int main()
{
    zmqpp::context context;
    zmqpp::socket server(context, zmqpp::socket_type::rep);

    server.bind("tcp://127.0.0.1:22000");

    while(1){
        zmqpp::message request;
        zmqpp::message response;
        json_object* json_pkt = NULL;

        server.receive(request);

        json_pkt = json_tokener_parse(request.get(0).c_str());
        json_object* json_resp = handle_command(json_pkt);
        char *resp = strdup(json_object_to_json_string(json_resp));
        response << resp;
        server.send(response);

        free(resp);
        json_object_put(json_pkt);
        json_object_put(json_resp);
    }
}
