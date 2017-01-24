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
#include "base64.h"

using namespace std;

ivmi_t ivmi_ctx;


json_object* serialize_trap(drakvuf_trap_t *trap){
    json_object* ret=json_object_new_object();
    string type;

    if (trap->type == BREAKPOINT){
        type="BREAKPOINT";
    }else if (trap->type == MEMACCESS){
        type="MEMACCESS";    
    }else if (trap->type == REGISTER){
        type="REGISTER";
    }else if (trap->type == DEBUG){
        type="DEBUG";
    }else if (trap->type == CPUID){
        type="CPUID";
    }else{
        type="INVALID";
    }

    json_object_object_add(ret,"type",json_object_new_string(type.c_str()));

    if (trap->type == BREAKPOINT){
        string addr_type, lookup_type;

        if (trap->breakpoint.lookup_type == LOOKUP_NONE){
            lookup_type="NONE";
        }else if(trap->breakpoint.lookup_type == LOOKUP_PID){
            lookup_type="PID";
        }else if(trap->breakpoint.lookup_type == LOOKUP_DTB){
            lookup_type="DTB";
        }else if(trap->breakpoint.lookup_type == LOOKUP_NAME){
            lookup_type="NAME";
        }else{
            lookup_type="INVALID";
        }
        json_object_object_add(ret,"lookup_type",json_object_new_string(lookup_type.c_str()));
        
        if (trap->breakpoint.addr_type == ADDR_PA){
            addr_type="PA";
            json_object_object_add(ret, "addr", json_object_new_int64(trap->breakpoint.addr));
        }else if(trap->breakpoint.addr_type == ADDR_VA){
            addr_type="VA";
            json_object_object_add(ret, "addr", json_object_new_int64(trap->breakpoint.addr));
        }else if(trap->breakpoint.addr_type == ADDR_RVA){
            addr_type="RVA";
            json_object_object_add(ret, "rva", json_object_new_int64(trap->breakpoint.rva));
        }else{
            addr_type="INVALID";
        }
        json_object_object_add(ret,"addr_type",json_object_new_string(addr_type.c_str()));
        json_object_object_add(ret,"module",json_object_new_string(trap->breakpoint.module));
    }
    // TODO MEMACCESS


    return ret;
}

json_object* serialize_x86_registers(x86_registers_t *regs){
    json_object* ret=json_object_new_object();
    
    json_object_object_add(ret,"rax",json_object_new_int64(regs->rax));
    json_object_object_add(ret,"rbx",json_object_new_int64(regs->rbx));
    json_object_object_add(ret,"rcx",json_object_new_int64(regs->rcx));
    json_object_object_add(ret,"rdx",json_object_new_int64(regs->rdx));
    json_object_object_add(ret,"rsp",json_object_new_int64(regs->rsp));
    json_object_object_add(ret,"rbp",json_object_new_int64(regs->rbp));
    json_object_object_add(ret,"rsi",json_object_new_int64(regs->rsi));
    json_object_object_add(ret,"rdi",json_object_new_int64(regs->rdi));
    json_object_object_add(ret,"r8",json_object_new_int64(regs->r8));
    json_object_object_add(ret,"r9",json_object_new_int64(regs->r9));
    json_object_object_add(ret,"r10",json_object_new_int64(regs->r10));
    json_object_object_add(ret,"r11",json_object_new_int64(regs->r11));
    json_object_object_add(ret,"r12",json_object_new_int64(regs->r12));
    json_object_object_add(ret,"r13",json_object_new_int64(regs->r13));
    json_object_object_add(ret,"r14",json_object_new_int64(regs->r14));
    json_object_object_add(ret,"r15",json_object_new_int64(regs->r15));
    json_object_object_add(ret,"rflags",json_object_new_int64(regs->rflags));
    json_object_object_add(ret,"dr7",json_object_new_int64(regs->dr7));
    json_object_object_add(ret,"rip",json_object_new_int64(regs->rip));
    json_object_object_add(ret,"cr0",json_object_new_int64(regs->cr0));
    json_object_object_add(ret,"cr2",json_object_new_int64(regs->cr2));
    json_object_object_add(ret,"cr3",json_object_new_int64(regs->cr3));
    json_object_object_add(ret,"cr4",json_object_new_int64(regs->cr4));
    json_object_object_add(ret,"sysenter_cs",json_object_new_int64(regs->sysenter_cs));
    json_object_object_add(ret,"sysenter_esp",json_object_new_int64(regs->sysenter_esp));
    json_object_object_add(ret,"sysenter_eip",json_object_new_int64(regs->sysenter_eip));
    json_object_object_add(ret,"msr_efer",json_object_new_int64(regs->msr_efer));
    json_object_object_add(ret,"msr_star",json_object_new_int64(regs->msr_star));
    json_object_object_add(ret,"msr_lstar",json_object_new_int64(regs->msr_lstar));
    json_object_object_add(ret,"fs_base",json_object_new_int64(regs->fs_base));
    json_object_object_add(ret,"gs_base",json_object_new_int64(regs->gs_base));
    json_object_object_add(ret,"cs_arbytes",json_object_new_int(regs->cs_arbytes));
    json_object_object_add(ret,"_pad",json_object_new_int(regs->_pad));
    return ret;
}

json_object* serialize_trap_info(drakvuf_trap_info_t *info){
    json_object* ret=json_object_new_object();
    json_object_object_add(ret, "vcpu", json_object_new_int(info->vcpu));
    json_object_object_add(ret, "altp2m_idx", json_object_new_int(info->altp2m_idx));
    json_object_object_add(ret, "procname", json_object_new_string(info->procname));
    json_object_object_add(ret, "userid", json_object_new_int64(info->userid));
    json_object_object_add(ret, "trap_pa", json_object_new_int64(info->trap_pa));
    json_object_object_add(ret, "regs", serialize_x86_registers(info->regs));
    json_object_object_add(ret, "trap", serialize_trap(info->trap));
    return ret;
}

static event_response_t cb(drakvuf_t drakvuf, drakvuf_trap_info_t *info){
    cout << "Breakpoint callback" << endl;

    if (ivmi_ctx.closing) return VMI_SUCCESS;

    zmqpp::message notification, ack;

    json_object* notify_json = serialize_trap_info(info);

    char *resp = strdup(json_object_to_json_string(notify_json));
    notification << resp;

    ivmi_ctx.notify->send(notification);

    free(resp);
    json_object_put(notify_json);
    
    // Blocking
    g_bit_lock(&ivmi_ctx.notify_lock, 1);

    return VMI_SUCCESS;
}

json_object* handle_notify_cont(){
    g_bit_unlock(&ivmi_ctx.notify_lock, 1);
    return json_object_new_string("OK");
}

json_object* handle_error(int32_t e){
    json_object* resp=json_object_new_object();
    json_object* errcode=json_object_new_int(e);
    json_object_object_add(resp, "error", errcode);
    json_object_put(errcode);
    return resp;
}

json_object* handle_trap_del(json_object* json_pkt){
    json_object* trap_name_json;
    string trap_name;

    json_object_object_get_ex(json_pkt,"trap_name",&trap_name_json);
    trap_name=json_object_get_string(trap_name_json);
    json_object_put(trap_name_json);
    if (ivmi_ctx.traps.find(trap_name) != ivmi_ctx.traps.end()){
        drakvuf_remove_trap(ivmi_ctx.drakvuf, ivmi_ctx.traps[trap_name], NULL);
        ivmi_ctx.traps.erase(trap_name);
        return json_object_new_string("OK");
    }else return handle_error(1);
}

json_object* handle_trap_add(json_object* json_pkt){
    // Best effort: We try to construct a valid trap, if libdrakvuf can't handle it, it's the users problem

    drakvuf_trap_t *trap = (drakvuf_trap_t*)malloc(sizeof(drakvuf_trap_t));

    json_object* json_trap = NULL;

    json_object* lookup_type_json = NULL;
    json_object* addr_type_json = NULL;
    json_object* addr_json = NULL;
    json_object* name_json = NULL;

    try{
         if (!json_object_object_get_ex(json_pkt,"trap",&json_trap)){
            throw 1;
        }

        if (!json_object_object_get_ex(json_trap,"lookup_type",&lookup_type_json)){
            throw 2;
        }
        if (!json_object_object_get_ex(json_trap,"addr_type",&addr_type_json)){
            throw 3;
        }
        if (!json_object_object_get_ex(json_trap,"addr",&addr_json)){
            throw 4;
        }
        if (!json_object_object_get_ex(json_trap,"name",&name_json)){
            throw 5;
        }
    
        char* lookup_type = strdup(json_object_get_string(lookup_type_json));
        char* addr_type = strdup(json_object_get_string(addr_type_json));
        char* name = strdup(json_object_get_string(name_json));
        addr_t addr = json_object_get_int64(addr_json);
        json_object_put(lookup_type_json);
        json_object_put(addr_type_json);
        json_object_put(addr_json);

        if (!strcmp(lookup_type, "NONE")){
            trap->breakpoint.lookup_type = LOOKUP_NONE;
        }else if (!strcmp(lookup_type, "DTB")){
            trap->breakpoint.lookup_type = LOOKUP_DTB;
        }else if (!strcmp(lookup_type, "PID")){
            trap->breakpoint.lookup_type = LOOKUP_PID;
        }else if (!strcmp(lookup_type, "NAME")){
            trap->breakpoint.lookup_type = LOOKUP_NAME;
        }

        if (!strcmp(addr_type, "PA")){
           trap->breakpoint.addr_type = ADDR_PA; 
        }else if (!strcmp(addr_type, "VA")){
           trap->breakpoint.addr_type = ADDR_VA; 
        }else if (!strcmp(addr_type, "RVA")){
           trap->breakpoint.addr_type = ADDR_RVA; 
        }

        free(lookup_type);
        free(addr_type);

        trap->type = BREAKPOINT;    
        trap->name = name;
        trap->cb = cb;
        trap->data = NULL;

        // Only seems to be relevant in vmi/inject_traps()
        if (trap->breakpoint.addr_type == ADDR_RVA){ 
            trap->breakpoint.rva = addr; 
        }else{
            trap->breakpoint.addr = addr; 
        }
        
        if (trap->breakpoint.addr_type == ADDR_VA){
            json_object* pid_json;
            json_object* dtb_json;
            if (json_object_object_get_ex(json_trap, "pid", &pid_json)){
                trap->breakpoint.pid = json_object_get_int64(pid_json);
                json_object_put(pid_json); 
            }else if (json_object_object_get_ex(json_trap, "dtb", &dtb_json)){
                trap->breakpoint.dtb = json_object_get_int64(dtb_json);
                json_object_put(dtb_json); 
            }
        }else if (trap->breakpoint.addr_type == ADDR_RVA){
            json_object* pid_json;
            json_object* proc_json;
            json_object* module_json;
            if (json_object_object_get_ex(json_trap, "pid", &pid_json)){
                trap->breakpoint.pid = json_object_get_int64(pid_json);
                json_object_put(pid_json); 
            }else if (json_object_object_get_ex(json_trap, "proc", &proc_json)){
                trap->breakpoint.proc = strdup(json_object_get_string(proc_json));
                json_object_put(proc_json); 
            }

            if (json_object_object_get_ex(json_trap, "module", &module_json)){
                trap->breakpoint.module = strdup(json_object_get_string(module_json));
                json_object_put(module_json); 
            }
       } 

        json_object_put(json_trap);
        if (!drakvuf_add_trap(ivmi_ctx.drakvuf, trap)){
            free(trap);
            return handle_error(255);
        }
        
        ivmi_ctx.traps[name]=trap;
        
        // We return the address of the trap pointer so it can be looked up for removal
        return json_object_new_int64(reinterpret_cast<size_t>(trap));
    }catch(int ex){
        if (lookup_type_json) json_object_put(lookup_type_json);
        if (addr_type_json) json_object_put(addr_type_json);
        if (addr_json) json_object_put(addr_json);
        free(trap);
        return handle_error(ex);
    }
}

json_object* handle_pause()
{
    if (ivmi_ctx.drakvuf){
        drakvuf_pause(ivmi_ctx.drakvuf);
        ivmi_ctx.paused = true;
    }else{
        return handle_error(1);
    }
    return json_object_new_string("OK");
}

json_object* handle_resume()
{
    if (ivmi_ctx.drakvuf){
        drakvuf_resume(ivmi_ctx.drakvuf);
        ivmi_ctx.paused = false;
    }else{
        return handle_error(1);
    }
    return json_object_new_string("OK");
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
    if (!ivmi_ctx.domain){
        return handle_error(0);
    }

    json_object* ret = json_object_new_object();
    
    os_t os_type = drakvuf_get_os_type(ivmi_ctx.drakvuf);
    addr_t kernel_base = drakvuf_get_kernel_base(ivmi_ctx.drakvuf);
    addr_t curr_proc = drakvuf_get_current_process(ivmi_ctx.drakvuf, 0); // TODO multi-CPU
    addr_t curr_thread = drakvuf_get_current_thread(ivmi_ctx.drakvuf, 0);
    char* process_name = drakvuf_get_process_name(ivmi_ctx.drakvuf, curr_proc);
    vmi_pid_t process_pid;
    drakvuf_get_process_pid(ivmi_ctx.drakvuf, curr_proc, &process_pid);

    json_object_object_add(ret,"domain",json_object_new_string(ivmi_ctx.domain));
    json_object_object_add(ret,"paused",json_object_new_int(ivmi_ctx.paused));
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


    if (!json_object_object_get_ex(json_pkt, "domain", &json_domain)){
        return handle_error(1);
    }
    if (!json_object_object_get_ex(json_pkt, "profile", &json_profile)){
        json_object_put(json_domain);
        return handle_error(2);
    }

    ofstream tmpf;
    string tmpn = tmpnam(NULL); // insecure
    tmpf.open(tmpn);
    cout << "Writing profile... " << tmpn << endl;
    tmpf << json_object_to_json_string(json_profile);
    tmpf.close();
    cout << "Profile ready." << endl;
    char *domain=strdup(json_object_get_string(json_domain));

    if (!drakvuf_init(&ivmi_ctx.drakvuf, domain, tmpn.c_str(), false)){
        json_object_put(json_profile);
        json_object_put(json_domain);
        free(domain);
        return handle_error(3);
    }    
    
    ivmi_ctx.domain = domain;
    g_bit_trylock(&ivmi_ctx.notify_lock,1);
    ivmi_ctx.closing = false;

    json_object_put(json_profile);
    json_object_put(json_domain);

    ivmi_ctx.drakvuf_loop = g_thread_new("drakvuf_loop", (GThreadFunc)drakvuf_loop, ivmi_ctx.drakvuf);
    drakvuf_pause(ivmi_ctx.drakvuf);
    ivmi_ctx.paused = true;
    return handle_info();
} 

json_object* handle_close(){
    if (ivmi_ctx.drakvuf){
        ivmi_ctx.closing=true;
        for (auto& t: ivmi_ctx.traps){
            drakvuf_remove_trap(ivmi_ctx.drakvuf,t.second,NULL);
        }
        ivmi_ctx.traps.clear();

        drakvuf_interrupt(ivmi_ctx.drakvuf,9);
        g_thread_join(ivmi_ctx.drakvuf_loop);

        remove(drakvuf_get_rekall_profile(ivmi_ctx.drakvuf));

        drakvuf_close(ivmi_ctx.drakvuf, false);
        free(ivmi_ctx.domain);
        ivmi_ctx.domain = NULL;
        ivmi_ctx.drakvuf = NULL;
    } 
    return json_object_new_string("OK");
}

json_object* handle_find_process(json_object* json_pkt){
    json_object* pid_json;
    json_object_object_get_ex(json_pkt, "pid", &pid_json); 

    addr_t eprocess_addr;
    int64_t pid=json_object_get_int64(pid_json);
    drakvuf_find_process(ivmi_ctx.drakvuf, pid, 0, &eprocess_addr);

    json_object_put(pid_json);

    return json_object_new_int64(eprocess_addr);
}

json_object* handle_process_modules(json_object* json_pkt){
    json_object* ret=json_object_new_array();

    json_object* pid_json;
    json_object_object_get_ex(json_pkt, "pid", &pid_json); 

    addr_t pid=json_object_get_int64(pid_json);
    addr_t eprocess_addr = 0;

    drakvuf_find_process(ivmi_ctx.drakvuf, pid, 0, &eprocess_addr);

    json_object_put(pid_json);

    addr_t module_list = 0;

    drakvuf_get_module_list(ivmi_ctx.drakvuf, eprocess_addr, &module_list);
    vmi_instance_t vmi=drakvuf_lock_and_get_vmi(ivmi_ctx.drakvuf);

    addr_t list_head = module_list;
    addr_t next_module = list_head;

    while (true) {
        addr_t tmp_next = 0;
        vmi_read_addr_va(vmi, next_module, pid, &tmp_next);

        if (list_head == tmp_next)
            break;

        json_object* mod_json=json_object_new_object();

        addr_t dllbase = 0;
        addr_t dllbase_offset = 0;
        addr_t dllname_offset = 0;
        drakvuf_get_struct_member_rva(drakvuf_get_rekall_profile(ivmi_ctx.drakvuf), "_LDR_DATA_TABLE_ENTRY", "DllBase", &dllbase_offset);
        drakvuf_get_struct_member_rva(drakvuf_get_rekall_profile(ivmi_ctx.drakvuf), "_LDR_DATA_TABLE_ENTRY", "BaseDllName", &dllname_offset);
        vmi_read_addr_va(vmi, next_module + dllbase_offset, pid, &dllbase);
        if (!dllbase){
            cout << "No dllbase" << endl;
            break;
        }
        unicode_string_t *us = vmi_read_unicode_str_va(vmi, next_module + dllname_offset, pid);
        unicode_string_t out;
        if (us){
            status_t status = vmi_convert_str_encoding(us, &out, "UTF-8");
            cout << out.contents << endl;
            if(VMI_SUCCESS == status){
                json_object_object_add(mod_json, "base", json_object_new_int64(dllbase));
                json_object_object_add(mod_json, "name", json_object_new_string((char*)out.contents));
                json_object_array_add(ret, mod_json);
            }
            vmi_free_unicode_str(us);
        }else{
            cout << "No us" << endl;
            break;
        }
        next_module = tmp_next;
        // https://github.com/v-p-b/drakvuf/blob/proctracer_rebase/src/plugins/proctracer/proctracer.cpp
    }
    return ret;
}

json_object* handle_process_list(){
    json_object *ret = json_object_new_array();

    vmi_instance_t vmi = drakvuf_lock_and_get_vmi(ivmi_ctx.drakvuf);

   try{ 
        if (!vmi){
            throw 1;
        }

        if (!ivmi_ctx.paused){
            drakvuf_pause(ivmi_ctx.drakvuf);
        }

        if (VMI_OS_LINUX == vmi_get_ostype(vmi)) {
            throw 2;
        }
        else if (VMI_OS_WINDOWS == vmi_get_ostype(vmi)) {
            // From DRAKVUF win_find_eprocess()
            addr_t current_process, next_list_entry;

            addr_t eprocess_tasks, eprocess_pid, eprocess_pname;

            if (VMI_FAILURE == drakvuf_get_struct_member_rva(drakvuf_get_rekall_profile(ivmi_ctx.drakvuf), "_EPROCESS", "ActiveProcessLinks", &eprocess_tasks)){
                throw 0x11;
            }
            if (VMI_FAILURE == drakvuf_get_struct_member_rva(drakvuf_get_rekall_profile(ivmi_ctx.drakvuf), "_EPROCESS", "UniqueProcessId", &eprocess_pid)){
                throw 0x12;
            }
            if (VMI_FAILURE == drakvuf_get_struct_member_rva(drakvuf_get_rekall_profile(ivmi_ctx.drakvuf), "_EPROCESS", "ImageFileName", &eprocess_pname)){
                throw 0x13;
            }

            status_t status = vmi_read_addr_ksym(vmi, "PsInitialSystemProcess", &current_process);
            if ( VMI_FAILURE == status ) throw 0x14;

            addr_t list_head = current_process + eprocess_tasks;
            addr_t current_list_entry = list_head;

            status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
            if ( VMI_FAILURE == status ) {
                throw 3;
            }

            do {
                vmi_pid_t pid;
                json_object* proc_elem = json_object_new_object();
                current_process = current_list_entry - eprocess_tasks;

                status = vmi_read_32_va(vmi, current_process + eprocess_pid, 0, (uint32_t*)&pid);
                if ( VMI_FAILURE == status ) {
                    throw 4;
                }

                char *procname = vmi_read_str_va(vmi, current_process + eprocess_pname, 0);

                /*if((find_pid != ~0 && pid == find_pid) || (find_procname && procname && !strcmp(procname, find_procname))) {
                    *eprocess_addr = current_process;
                    free(procname);
                }*/
                json_object_object_add(proc_elem, "pid", json_object_new_int64(pid));
                json_object_object_add(proc_elem, "process_name", json_object_new_string(procname));
                json_object_object_add(proc_elem, "eprocess", json_object_new_int64(current_process));
                json_object_array_add(ret, proc_elem);

                free(procname);

                current_list_entry = next_list_entry;

                status = vmi_read_addr_va(vmi, current_list_entry, 0, &next_list_entry);
                if ( VMI_FAILURE == status ) {
                    throw 6;
                }

            } while (next_list_entry != list_head);
        }else{

            throw 2;
        }


        if (!ivmi_ctx.paused){
            drakvuf_resume(ivmi_ctx.drakvuf);
        }
        drakvuf_release_vmi(ivmi_ctx.drakvuf);
        return ret;
    }catch(int ex){
        return handle_error(ex);
    }
}

json_object* handle_mem_read(json_object *json_pkt){
    json_object* pid_json;
    json_object* addr_json;
    json_object* len_json;

    json_object_object_get_ex(json_pkt, "pid", &pid_json);
    json_object_object_get_ex(json_pkt, "addr", &addr_json);
    json_object_object_get_ex(json_pkt, "len", &len_json);

    addr_t pid;
    addr_t addr;
    uint32_t len;

    pid=json_object_get_int64(pid_json);
    addr=json_object_get_int64(addr_json);
    len=json_object_get_int(len_json);

    json_object_put(pid_json);
    json_object_put(addr_json);
    json_object_put(len_json);

    void* buf=malloc(len);

    if (!buf){
        return handle_error(1);
    }

    vmi_instance_t vmi=drakvuf_lock_and_get_vmi(ivmi_ctx.drakvuf); 
    if (!ivmi_ctx.paused){
        drakvuf_pause(ivmi_ctx.drakvuf); // Consistent read
    }
    size_t read=0;
    if (pid==0){
        read=vmi_read_pa(vmi, addr, buf, len);
    }else{
        read=vmi_read_va(vmi, addr, pid, buf, len);
    }
    if (!ivmi_ctx.paused){
        drakvuf_resume(ivmi_ctx.drakvuf);
    }
    drakvuf_release_vmi(ivmi_ctx.drakvuf);

    if (read!=len){
        free(buf);
        return handle_error(2);
    }

    string mem=base64_encode(reinterpret_cast<const unsigned char*>(buf), len);
    free(buf);
    return json_object_new_string(mem.c_str());
}

json_object* handle_mem_write(json_object *json_pkt){
    json_object* pid_json;
    json_object* addr_json;
    json_object* contents_json;

    json_object_object_get_ex(json_pkt, "pid", &pid_json);
    json_object_object_get_ex(json_pkt, "addr", &addr_json);
    json_object_object_get_ex(json_pkt, "contents", &contents_json);

    addr_t pid;
    addr_t addr;
    char* contents_b64;

    pid=json_object_get_int64(pid_json);
    addr=json_object_get_int64(addr_json);
    contents_b64=strdup(json_object_get_string(contents_json));

    json_object_put(pid_json);
    json_object_put(addr_json);
    json_object_put(contents_json);

    string scontents_b64=contents_b64;
    string sbuf=base64_decode(scontents_b64);

    void* buf=malloc(sbuf.length());
    memcpy(buf, sbuf.data(), sbuf.length());

    vmi_instance_t vmi=drakvuf_lock_and_get_vmi(ivmi_ctx.drakvuf); 
    if (!ivmi_ctx.paused){
        drakvuf_pause(ivmi_ctx.drakvuf); // Consistent write
    }
    size_t wrote=0;
    if (pid==0){
        wrote=vmi_write_pa(vmi, addr, buf, sbuf.length());
    }else{
        wrote=vmi_write_va(vmi, addr, pid, buf, sbuf.length());
    }
  
    if (ivmi_ctx.paused){ 
        drakvuf_resume(ivmi_ctx.drakvuf);
    }
    drakvuf_release_vmi(ivmi_ctx.drakvuf);

    free(buf);
    free(contents_b64);
    if (wrote!=sbuf.length()){
        return handle_error(2);
    }

    return json_object_new_int(wrote);
}

json_object* handle_reg_get(json_object* json_pkt){
    json_object* reg_json;
    json_object* vcpuid_json;

    reg_t vcpuid;
    reg_t value;

    if (!json_object_object_get_ex(json_pkt,"reg",&reg_json)){
        return handle_error(1);
    }
    if (!json_object_object_get_ex(json_pkt,"vcpuid",&vcpuid_json)){
        vcpuid=0;
    }else{
        vcpuid=json_object_get_int(vcpuid_json);
        json_object_put(vcpuid_json);
    }

    string reg=json_object_get_string(reg_json);
    json_object_put(reg_json);

    if (ivmi_regs.count(reg)==1){
        vmi_instance_t vmi=drakvuf_lock_and_get_vmi(ivmi_ctx.drakvuf);
        vmi_get_vcpureg(vmi, &value, ivmi_regs[reg], vcpuid); 
        drakvuf_release_vmi(ivmi_ctx.drakvuf);
        return json_object_new_int64(value);
    }else{
        return handle_error(2);
    }
}

json_object* handle_reg_set(json_object* json_pkt){
    json_object* reg_json;
    json_object* vcpuid_json;
    json_object* value_json;

    reg_t vcpuid;
    int64_t value;

    if (!json_object_object_get_ex(json_pkt,"reg",&reg_json) || !json_object_object_get_ex(json_pkt,"value",&value_json)){
        return handle_error(1);
    }

    if (!json_object_object_get_ex(json_pkt,"vcpuid",&vcpuid_json)){
        vcpuid=0;
    }else{
        vcpuid=json_object_get_int(vcpuid_json);
        json_object_put(vcpuid_json);
    }

    string reg=json_object_get_string(reg_json);
    value=json_object_get_int64(value_json);
    json_object_put(reg_json);
    json_object_put(value_json);

    if (ivmi_regs.count(reg)==1){
        vmi_instance_t vmi=drakvuf_lock_and_get_vmi(ivmi_ctx.drakvuf);
        vmi_set_vcpureg(vmi, value, ivmi_regs[reg], vcpuid); 
        drakvuf_release_vmi(ivmi_ctx.drakvuf);
    }
    return json_object_new_string("OK"); 
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
                json_resp=handle_mem_read(json_pkt);
                break;
            case CMD_MEM_W:
                json_resp=handle_mem_write(json_pkt);
                break;
            case CMD_REG_R:
                json_resp=handle_reg_get(json_pkt);
                break;
            case CMD_REG_W:
                json_resp=handle_reg_set(json_pkt);
                break;
            case CMD_TRAP_ADD:
                json_resp=handle_trap_add(json_pkt);
                break;
            case CMD_TRAP_DEL:
                json_resp=handle_trap_del(json_pkt);
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
            case CMD_PROC_MODULES:
                json_resp=handle_process_modules(json_pkt);
                break;
            case CMD_NOTIFY_CONT:
                json_resp=handle_notify_cont();
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
    zmqpp::socket notify(context, zmqpp::socket_type::push);

    server.bind("tcp://127.0.0.1:22000");
    notify.bind("tcp://127.0.0.1:22001");
    ivmi_ctx.notify = &notify;
    ivmi_ctx.notify_lock=0;

    while(1){
        zmqpp::message request;
        zmqpp::message response;
        json_object* json_pkt = NULL;

        server.receive(request);
        char* r=strdup(request.get(0).c_str());

        json_pkt = json_tokener_parse(r);
        free(r);

        json_object* json_resp = handle_command(json_pkt);
        char *resp = strdup(json_object_to_json_string(json_resp));
        response << resp;
        server.send(response);

        free(resp);
        if (json_pkt) json_object_put(json_pkt);
        if (json_resp) json_object_put(json_resp);
    }
}
