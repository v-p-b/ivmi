#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <libdrakvuf/libdrakvuf.h>
#include <unistd.h>
#include <fcntl.h>
#include <json-c/json.h>

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

json_object* handle_command(json_object *json_cmd){
    int32_t cmd=json_object_get_int(json_cmd);
    printf("Got command: %d\n",cmd);
    return json_tokener_parse("{\"resp\":43}");
}

int main()
{
 
    uint16_t len=0;
    int listen_fd, comm_fd;
 
    struct sockaddr_in servaddr;
    int iMode=0;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd<0){
        printf("Socket error!\n");
    }
    ioctl(listen_fd, FIONBIO, &iMode);  
    // Test if the socket is in non-blocking mode:
    if(fcntl(listen_fd, F_GETFL) & O_NONBLOCK) {
            printf("Socket is non-blocking\n");
    }
    bzero( &servaddr, sizeof(servaddr));
 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port = htons(22000);
 
    bind(listen_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
 
    listen(listen_fd, 10);
 
    comm_fd = accept(listen_fd, (struct sockaddr*) NULL, NULL);

    /*drakvuf_t drakvuf;

    drakvuf_init(&drakvuf, "", "", false);    */
    char* pkt = NULL;
    int32_t cmd = 0;
    json_object* json_pkt = NULL;
    json_object* json_cmd = NULL;
    while(1){
        len=0;
        printf("Read: %ld \n", recv(comm_fd, &len, 2, MSG_WAITALL));
        printf("Packet length: %d\n", len);
        if (len==0xffff){
            fprintf(stderr,"Invalid length!\n");    
            continue;
        }
        if (len==0){
            printf("Disconnected, exiting...\n");
            break;
        }

        try{
            pkt=(char*)malloc(len+1);
            
            if (!pkt){
                fprintf(stderr,"Memory allocation error!\n");
                continue;
            }

            if (recv(comm_fd, pkt, len, MSG_WAITALL)<len){
                fprintf(stderr,"Receive error!\n");    
                throw -1;
            }
            pkt[len] = 0;
            printf("Packet: %s\n", pkt);
            json_pkt = json_tokener_parse(pkt);
            if (!json_object_object_get_ex(json_pkt, "cmd",&json_cmd)){
                fprintf(stderr,"Invalid packet!\n");
                throw -1;
            }
            json_object* json_resp = handle_command(json_cmd);
            char *resp = strdup(json_object_to_json_string(json_resp));
            size_t resp_len = strlen(resp);
            if (resp_len > 0xffff-1){
                fprintf(stderr,"Answer too big!\n");
                free(resp);
                json_object_put(json_resp);
                throw -1;
            }
            printf("Response length: %ld\n", resp_len);
            char *resp_pkt=(char*)malloc(resp_len+2);
            strncpy(resp_pkt+2,resp,resp_len);
            resp_pkt[0] = resp_len & 0xff;
            resp_pkt[1] = (resp_len & 0xff00) >> 8;
            send(comm_fd,resp_pkt,resp_len+2,0);

            free(pkt);
            free(resp_pkt);
            free(resp);
            json_object_put(json_cmd);
            json_object_put(json_pkt);
            json_object_put(json_resp);
        }catch(int ex){
            fprintf(stderr,"Exception handling: %x",ex);
            free(pkt);
            json_object_put(json_cmd);
            json_object_put(json_pkt);
        }
    }
    close(comm_fd);
}
