#include <string>
#include <iostream>
#include <libdrakvuf/libdrakvuf.h>
#include <unistd.h>
#include <json-c/json.h>
#include <zmqpp/zmqpp.hpp>

using namespace std;

void* handle_pause(drakvuf_t drakvuf)
{
    return NULL;
}

void* handle_resume()
{
    return NULL;
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

json_object* handle_command(json_object *json_pkt){
    json_object* json_cmd = NULL;
    try{
        if (!json_object_object_get_ex(json_pkt, "cmd",&json_cmd)){
            fprintf(stderr,"Invalid packet!\n");
            throw -1;     
        }

        int32_t cmd=json_object_get_int(json_cmd);
        printf("Got command: %d\n",cmd);
        
        json_object_put(json_cmd);

        return json_tokener_parse("{\"resp\":43}");
    }catch (int ex){ 
        json_object_put(json_cmd);
        return json_tokener_parse("{\"error\":-1}");
    }
}

int main()
{
    zmqpp::context context;
    zmqpp::socket server(context, zmqpp::socket_type::rep);

    server.bind("tcp://127.0.0.1:22000");

    /*drakvuf_t drakvuf;

    drakvuf_init(&drakvuf, "", "", false);    */
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
    }
}
