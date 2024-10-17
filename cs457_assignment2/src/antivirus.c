#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <regex.h>
#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <sys/inotify.h>
#include <signal.h>
#include <poll.h>
#include <fcntl.h>
#include <time.h>
#define MSG_SIZE 1024
#define CHUNK_SIZE 1024
#define REGEX   "((https?|ftp)://|www.)[-a-zA-Z0-9+&@#/?=~_|!:,.;]*[-a-zA-Z0-9+&@#/=~_|]"
#define MAX 100


void printInfo(char* msg){
    char* mon[]={"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    printf("[INFO] [%d] [%02d-%s-%d %02d:%02d:%02d] %s\n", getpid(), tm.tm_mday, mon[tm.tm_mon], tm.tm_year - 100 , tm.tm_hour, tm.tm_min, tm.tm_sec,msg);
}
struct url{
    char* domain;
    char* file;
    char* path;
    int exec;
    int res;
    struct url* next;
}*head=NULL;
struct ransom{
    char* file;
    int state;    // 0 - none 1 - opened 2 - file  created 3 file modified 4 file deleted
    struct ransom* next;
}*head_ransom=NULL;


void printURL(struct url* head){
    struct url* temp=head->next;

    printf("\n\n ===================================================================================================================================================\n");
    printf("|           FILE           |                     PATH                 |                       DOMAIN                        | EXECUTABLE |  RESULT  |\n");
    printf(" ===================================================================================================================================================\n");
    while(temp!=NULL){
        printf("| %-24s | %-40s | %-51s | ",temp->file,temp->path,temp->domain);
        if(temp->exec==1){
            printf("%3s%s%3s | ","","True","");
        }else{
            printf("%3s%s%2s | ","","False","");
        }
        if(temp->res){
            printf("\x1B[32m%-2s%s%2s\x1B[0m |\n","","Safe","");
        }else{
            printf("\x1B[31m%-8s\x1B[0m |\n"," Malware");
        }
        temp=temp->next;
    }
    printf(" ===================================================================================================================================================\n\n");
}

int fd;
void sigintHandler(int sig_num)
{
    printf("\nAre you sure you want to terminate? [y/n] ");
    char c;
    scanf("%c",&c);
    if(c=='y'){
        printInfo("Terminating ...");
        close(fd);
        struct ransom * temp = head_ransom;
        while(temp){
            struct ransom * t = temp;
            temp=temp->next;
            free(t->file);
            free(t);
        }
        exit(0);
    }else{
        printInfo("Continuing ...");
        getchar();
    }
}

int slice(int key){
    int a0,a1,a2;
    char msg[MSG_SIZE];
    srand(time(NULL));
    sprintf(msg, "Generating shares for key '%d'", key);
    printInfo(msg);
    printf("\n");
    a0=key;
    a1=rand()%997+1;
    a2=rand()%997+1;
    for(int i=1;i<=10;i++){
        printf("(%d,%d)\n",i,(a2*(i*i) + a1*i + a0));
    }
    return 0;
}
int unlock(int* x,int* y,int n){
    int a0,a1,a2;
    char msg[MSG_SIZE];
    int r[3],x1,x2,x3,y1,y2,y3;
    sprintf(msg, "Received %d shares",n);
    printInfo(msg);

    r[0]=rand()%n;
    do r[1]=(rand()%n); while(r[1]==r[0]);
    do r[2]=(rand()%n); while(r[2]==r[0]||r[2]==r[1]);
    
    x1=x[r[0]];
    x2=x[r[1]];
    x3=x[r[2]];
    y1=y[r[0]];
    y2=y[r[1]];
    y3=y[r[2]];


    a2=(y1*(x2-x3)+y2*(x3-x1)+y3*(x1-x2))/((x1-x2)*(x1-x3)*(x2-x3));
    a1=(y1-y2)/(x1-x2)-a2*(x1+x2);
    a0=y1-a2*x1*x1-a1*x1;
    
    sprintf(msg, "Computed that a=%d and b=%d",a2,a1);
    printInfo(msg);
    sprintf(msg, "Encryption key is: %d",a0);
    printInfo(msg);
    return 0;
}
int monitor (char* path){
    struct stat sb;
    if(!(stat(path, &sb) == 0 && S_ISDIR(sb.st_mode))){
        printf("Error: could not open directory\n");
        return 1;
    }
    
    fd = inotify_init();
    int wd= inotify_add_watch(fd, path,IN_IGNORED| IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVE_SELF | IN_DELETE_SELF | IN_ATTRIB | IN_ACCESS | IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_MOVED_FROM | IN_Q_OVERFLOW);
    int n;
    if(fd<0){
        printf("Error: inotify_init\n");
        return 1;
    }
    if(wd<0){
        printf("Error: inotify_add_watch\n");
        close(fd);
        return 1;
    }
    char msg[MSG_SIZE];
    char buf[4096];
    snprintf(msg, sizeof(msg), "Waiting for events...");
    printInfo(msg);
    printf("\n");
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    while(1){
        poll(fds,1,-1);
        n=read(fd,buf,4096);
        if(n<0){
            printf("Error: read\n");
            return 1;
        }
        int i=0;
        while(i<n){
            struct inotify_event *event = (struct inotify_event *) &buf[i];
            if(event->mask & IN_IGNORED){
                printf("Watch was removed\n");
                return 0;
            }
            if(event->mask & IN_Q_OVERFLOW){
                printf("Queue overflow\n");
                return 0;
            }
            
            if(event->mask & IN_ISDIR){
                if( (strlen(event->name)==0||event->name[0]==' ')||event->name==NULL){
                    printf("Directory '%s' ",path);
                }else{
                    printf("Directory '%s' ",event->name);
                }

            }else{
                printf("File '%s' ",event->name);
            }
            if(event->mask & IN_MODIFY){
                printf("was modified\n");
                int flag=0;
                struct ransom * temp = head_ransom;
                while(temp){
                    if(strstr(event->name,temp->file)!=NULL&&temp->file[0]==event->name[0]){
                        flag=1;
                        break;
                    }
                    temp=temp->next;
                }
                if(flag==1){
                    if(event->name[strlen(temp->file)]=='.'&&((event->name[strlen(temp->file)+1]>='a'&&event->name[strlen(temp->file)+1]<='z')|| (event->name[strlen(temp->file)+1]>='A'&&event->name[strlen(temp->file)+1]<='Z'))){
                        temp->state=3;
                    }
                }
            }
            if(event->mask & IN_CREATE){
                int flag=0;
                printf("was created\n");
                struct ransom * temp = head_ransom;
                while(temp){
                    if(strstr(event->name,temp->file)!=NULL&&temp->file[0]==event->name[0]){
                        flag=1;
                        break;
                    }
                    temp=temp->next;
                }
                if(flag==1){
                    if(event->name[strlen(temp->file)]=='.'&&((event->name[strlen(temp->file)+1]>='a'&&event->name[strlen(temp->file)+1]<='z')|| (event->name[strlen(temp->file)+1]>='A'&&event->name[strlen(temp->file)+1]<='Z'))){
                        temp->state=2;
                    }
                }
            }
            if(event->mask & IN_MOVE_SELF){
                printf("was moved\n");
            }
            if(event->mask & IN_ATTRIB){
                printf("attributes were changed\n");
            }
            if(event->mask & IN_DELETE_SELF){
                printf("was deleted from watched directory\n");
            }
            if(event->mask & IN_DELETE){
                printf("was deleted from watched directory\n");
                struct ransom * temp = head_ransom;
                while(temp){
                    if(strcmp(temp->file,event->name)==0){
                        if(temp->state==3){
                            temp->state=4;
                        }
                        break;
                    }
                    temp=temp->next;
                }
                if(temp&&temp->state==4){
                    printf("\033[31m[WARN] Ransomware attack detected on file %s \033[0m\n",temp->file);
                    temp->state=0;
                }
            }
            if(event->mask & IN_ACCESS){
                printf("was accessed\n");
            }
            if(event->mask & IN_OPEN){
                printf("was opened\n");
                struct ransom * temp = malloc(sizeof(struct ransom));
                temp->file=strdup(event->name);
                temp->state=1;
                temp->next=NULL;
                if(!head_ransom) {
                    head_ransom=temp;
                } else {
                    struct ransom * t = head_ransom;
                    while(t->next) {
                        t = t->next;
                    }
                    t->next = temp;
                }
            }
            if(event->mask & IN_CLOSE_NOWRITE){
                printf("that was not opened for writing was closed\n");
                struct ransom * temp = head_ransom;
                struct ransom * prev = NULL;
                while(temp){
                    if(strcmp(temp->file,event->name)==0){
                        if(temp->state==1){
                            temp->state=0;
                        }
                        break;
                    }
                    prev=temp;
                    temp=temp->next;
                }
                if(temp&&temp->state==0){
                    if(prev){
                        prev->next=temp->next;
                    }else{
                        head_ransom=temp->next;
                    }
                    free(temp->file);
                    free(temp);
                }
            }
            if(event->mask & IN_CLOSE_WRITE){
                printf("that was opened for writing was closed\n");
                struct ransom * temp = head_ransom;
                struct ransom * prev = NULL;
                while(temp){
                    if(strcmp(temp->file,event->name)==0){
                        if(temp->state==1){
                            temp->state=0;
                        }
                        break;
                    }
                    prev=temp;
                    temp=temp->next;
                }
                if(temp&&temp->state==0){
                    if(prev){
                        prev->next=temp->next;
                    }else{
                        head_ransom=temp->next;
                    }
                    free(temp->file);
                    free(temp);
                }
            }
            if(event->mask & IN_MOVED_FROM){
                printf("was moved\n");
            }

            i+=sizeof(struct inotify_event)+event->len;
        }

    }
    close(fd);
    return 0;
}
int inspect(FILE* file,char* path,char* file_name){
    char* buffer;
    char URL[CHUNK_SIZE];
    size_t read_bytes;
    regex_t regex;
    regmatch_t pmatch[1];
    int reti;
    buffer=malloc(CHUNK_SIZE);
    reti = regcomp(&regex, REGEX,REG_EXTENDED | REG_ICASE | REG_NEWLINE);
    if (reti) {
        fprintf(stderr, "Could not compile regex\n");
        return -1;
    }
    while ((read_bytes= fread(buffer, 1, CHUNK_SIZE, file)) > 0) {
        char *b=buffer;
        while(1){
            reti = regexec(&regex, b, 1, pmatch,0);
            if (reti) {
                if (reti != REG_NOMATCH) {
                    fprintf(stderr, "Regex match failed\n");
                    return -1;
                }
                break;
            }else{
                    head->next=malloc(sizeof(struct url));
                    head=head->next;
                    head->domain=malloc(pmatch[0].rm_eo - pmatch[0].rm_so+1);
                    head->domain[0]='\0';
                    strncat(head->domain, b + pmatch[0].rm_so, pmatch[0].rm_eo - pmatch[0].rm_so);
                    head->file=strdup(file_name);
                    head->path=strdup(path);
                    head->res=1;
                    head->exec=0;

                    struct stat sb;

                    sprintf(URL,"%s/%s",path,file_name);
    
                    if(stat(URL, &sb) == 0 && sb.st_mode & S_IXUSR){
                        head->exec=1;
                    }
                    head->next=NULL;
                }
                b += pmatch[0].rm_eo;
                memset(pmatch,0,sizeof(regmatch_t));
        }
    }
    free(buffer);
    regfree(&regex);
    return 0;

}

struct json{
    char* data;
    size_t size;
};
size_t write_callback(void *ptr, size_t size, size_t nmemb, void* data){
    struct json* jdata = (struct json*)data;
    size_t realsize = size * nmemb;
    jdata->data = realloc(jdata->data, jdata->size + realsize + 1);
    if(jdata->data == NULL) {
        fprintf(stderr, "Not enough memory (realloc returned NULL)\n");
        exit(EXIT_FAILURE);
    }
    memcpy(&(jdata->data[jdata->size]), ptr, realsize);
    jdata->size += realsize;
    jdata->data[jdata->size] = 0;
    return realsize;
}
int checkURL() {
    CURL *curl;
    CURLcode res;
    struct json* json1 = calloc(1, sizeof(struct json));
    struct json* json2 = calloc(1, sizeof(struct json));
    char query[CHUNK_SIZE];
    struct curl_slist *header = NULL;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();

    if(curl) {
        struct url* temp = head;
        while(temp != NULL) {
            if(temp->domain != NULL) {
                json1->data = NULL;
                json1->size = 0;
                json2->data = NULL;
                json2->size = 0;
                int off=0;
                if(strstr(temp->domain, "http://") != NULL ) {
                    off=7;
                }else if(strstr(temp->domain, "https://") != NULL){
                    off=8;
                }
                snprintf(query, sizeof(query), "https://1.1.1.3/dns-query?name=%s", temp->domain+off);
                header = curl_slist_append(header, "accept: application/dns-json");

                curl_easy_setopt(curl, CURLOPT_URL, query);
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, json1);

                res = curl_easy_perform(curl);
                if(res != CURLE_OK) {
                    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                    exit(1);
                }

                curl_slist_free_all(header);
                header = NULL;

                snprintf(query, sizeof(query), "https://family.cloudflare-dns.com/dns-query?name=%s", temp->domain+off);
                header = curl_slist_append(header, "accept: application/dns-json");

                curl_easy_setopt(curl, CURLOPT_URL, query);
                curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
                curl_easy_setopt(curl, CURLOPT_WRITEDATA, json2);

                res = curl_easy_perform(curl);
                if(res != CURLE_OK) {
                    fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                    exit(1);
                }

                curl_slist_free_all(header);
                header = NULL;

                if(json1->data != NULL && json2->data != NULL) {
                    if(strstr(json1->data, "Censored") != NULL && strstr(json2->data, "Censored") != NULL) {
                        temp->res = 0;
                    } else {
                        temp->res = 1;
                    }
                }
                free(json1->data);
                free(json2->data);
            }
            temp = temp->next;
        }

        curl_easy_cleanup(curl);
    }
    free(json1);
    free(json2);
    curl_global_cleanup();
    return 0;
}

int scan(FILE* file){
    char bitcoin_addr[] = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6";
    unsigned char signature[16]={0x98, 0x1d, 0x00, 0x00, 0xec, 0x33, 0xff, 0xff, 0xfb, 0x06, 0x00, 0x00, 0x00, 0x46, 0x0e, 0x10};
    unsigned char buffer[CHUNK_SIZE];
    size_t read_bytes;
    size_t bytes_found[2]= {0,0};

    EVP_MD_CTX *mdctx_md5;
    EVP_MD_CTX *mdctx_sha;
    unsigned char md_value_md5[EVP_MAX_MD_SIZE];
    unsigned char md_value_sha[EVP_MAX_MD_SIZE];
    unsigned int md_len_md5;
    unsigned int md_len_sha;
    const EVP_MD *md_md5;
    const EVP_MD *md_sha;

    unsigned char md_expected_md5[16] = { 0x85, 0x57, 0x8c, 0xd4, 0x40, 0x4c, 0x6d, 0x58, 0x6c, 0xd0, 0xae, 0x1b, 0x36, 0xc9, 0x8a, 0xca};
    unsigned char md_expected_sha256[32] = { 0xd5, 0x6d, 0x67, 0xf2, 0xc4, 0x34, 0x11, 0xd9, 0x66, 0x52, 0x5b, 0x32, 0x50, 0xbf, 0xaa, 0x1a, 0x85, 0xdb, 0x34, 0xbf, 0x37, 0x14, 0x68, 0xdf, 0x1b, 0x6a, 0x98, 0x82, 0xfe, 0xe7, 0x88, 0x49};

    md_md5 = EVP_md5();
    mdctx_md5 = EVP_MD_CTX_create();

    EVP_DigestInit_ex(mdctx_md5, md_md5, NULL);

    md_sha = EVP_sha256();
    mdctx_sha = EVP_MD_CTX_create();

    EVP_DigestInit_ex(mdctx_sha, md_sha, NULL);

    while ((read_bytes= fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (size_t i = 0; i < read_bytes; ++i) {
            if (buffer[i] == signature[bytes_found[0]]) {
                bytes_found[0]++;
                if (bytes_found[0] == 16) {
                    EVP_MD_CTX_free(mdctx_md5);
                    EVP_MD_CTX_free(mdctx_sha);
                    return 1;
                }
            } else {
                bytes_found[0] = 0;
            }

            if (buffer[i] == bitcoin_addr[bytes_found[1]]) {
                bytes_found[1]++;
                if (bytes_found[1] == 42) {
                    EVP_MD_CTX_free(mdctx_md5);
                    EVP_MD_CTX_free(mdctx_sha);
                    return 2;
                }
            } else {
                bytes_found[1] = 0;
            }
        }
        EVP_DigestUpdate(mdctx_md5, buffer, read_bytes);
        EVP_DigestUpdate(mdctx_sha, buffer, read_bytes);
    }

    EVP_DigestFinal_ex(mdctx_md5, md_value_md5, &md_len_md5);

    if (memcmp(md_value_md5, md_expected_md5, 16) == 0) {
        EVP_MD_CTX_free(mdctx_md5);
        EVP_MD_CTX_free(mdctx_sha);
        return 3;
    }

    EVP_DigestFinal_ex(mdctx_sha, md_value_sha, &md_len_sha);

    if (memcmp(md_value_sha, md_expected_sha256, 32) == 0) {
        EVP_MD_CTX_free(mdctx_md5);
        EVP_MD_CTX_free(mdctx_sha);
        return 4;
    }
    EVP_MD_CTX_free(mdctx_md5);
    EVP_MD_CTX_free(mdctx_sha);
    return 0;
}
size_t get_folder_size(const char* filename) {
    DIR* dir=opendir(filename);
    struct dirent* ent;
    size_t size=0;
    if(!dir){
        return 0;
    }
    while((ent=readdir(dir))!=NULL){
        if(ent->d_type==DT_REG){
            size++;
        }else{
            if(strcmp(ent->d_name,".")!=0 && strcmp(ent->d_name,"..")!=0){
                char *path_s=malloc(strlen(filename)+strlen(ent->d_name)+2);
                strcpy(path_s,filename);
                strcat(path_s,"/");
                strcat(path_s,ent->d_name);
                size+=get_folder_size(path_s);
                free(path_s);
            }
        }
    }
    closedir(dir);
    return size;
}

void checkFolder(DIR* dir,char* path,int call,int how){
    static int files=0;
    static int files_processed=0;
    static char** report={0};
    static int report_size=0;
    static int infected=0;
    char msg[MSG_SIZE];
    if(call){
        files=get_folder_size(path);
        snprintf(msg, sizeof(msg), "Found %d files", files);
        printInfo(msg);
        if(how!=2){
            report=malloc(files*sizeof(char*));
        }
        printInfo("Searching...");
    }
    if(dir) {
        struct dirent* ent;
        if((ent = readdir(dir)) != NULL) {
            if(ent->d_type == DT_REG) {
                checkFolder(dir,path,0,how);
                char *path_s=malloc(strlen(path)+strlen(ent->d_name)+2);
                strcpy(path_s,path);
                strcat(path_s,"/");
                strcat(path_s,ent->d_name);
                FILE* file = fopen(path_s, "r");
                free(path_s);
                if(!file) {
                    printf("Error: %s could not open file\n",path_s);
                     return;
                }
                if(how==1){
                    int res=scan(file);
                    files_processed++;
                    if(res>0) {
                            strcpy(msg,"");
                            snprintf(msg, sizeof(msg)+10,"%s/%s:",path,ent->d_name);
                            if(res==1){
                                strcat(msg,"REPORTED_VIRUS ");
                            }
                            if(res==2){
                                strcat(msg,"REPORTED_BITCOIN ");
                            }
                            if(res==3){
                                strcat(msg,"REPORTED_MD5_HASH ");
                            }
                            if(res==4){
                                strcat(msg,"REPORTED_SHA256_HASH ");
                            }
                            strcat(msg,"\n");

                            report[report_size]=malloc(strlen(msg)+1);
                            strcpy(report[report_size],msg);
                            report_size++;
                            infected++;
                    }
                }else if( how==2){
                    inspect(file,path,ent->d_name);
                    files_processed++;
                }

                fclose(file);
            }else if(ent->d_type == DT_DIR && strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
                char *path_s=malloc(strlen(path)+strlen(ent->d_name)+2);
                strcpy(path_s,path);
                strcat(path_s,"/");
                strcat(path_s,ent->d_name);
                DIR* subdir = opendir(path_s);
                if(subdir) {
                    checkFolder(subdir,path_s,0,how);
                    closedir(subdir);
                    free(path_s);
                } else {
                    printf("Error: could not open directory %s\n", ent->d_name);
                    free(path_s);
                }
                checkFolder(dir,path,0,how);
            }else{
                checkFolder(dir,path,0,how);
            }
        }

    } else {
        printf("Error: could not open directoryyy\n");
    }
    if(call==1&&how!=2){
        closedir(dir);
        snprintf(msg, sizeof(msg), "Operation finished");
        printInfo(msg);
        snprintf(msg, sizeof(msg), "Processed %d files \033[0;31mFound %d infected\033[0m", files_processed,infected);
        printInfo(msg);
        printf("\n");
        for(int i=0;i<report_size;i++){
            printf("%s",report[i]);
            free(report[i]);
        }
        free(report);
    }
}
int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("Usage: %s <operation>\n", argv[0]);
        return 1;
    }
    char msg[MSG_SIZE];
    if(strcmp(argv[1], "scan") == 0) {
        if(argc != 3) {
            printf("Usage: %s scan <path>\n", argv[0]);
            return 1;
        }
        printInfo("Application Started");
        DIR* dir = opendir(argv[2]);
        if(dir) {
            snprintf(msg, sizeof(msg), "Scanning directory %s", argv[2]);
            printInfo(msg);
            checkFolder(dir,argv[2],1,1);
        } else {
            printf("Error: could not open directory\n");
            return 1;
        }
    }else if(strcmp(argv[1], "inspect") == 0){
        if(argc != 3) {
            printf("Usage: %s inspect <path>\n", argv[0]);
            return 1;
        }
        printInfo("Application Started");
        DIR* dir = opendir(argv[2]);
        struct url * temp;
        head= malloc(sizeof(struct url));
        temp=head;
        head->domain=NULL;
        head->file=NULL;
        head->path=NULL;
        head->next=NULL;
        if(dir) {
            snprintf(msg, sizeof(msg), "Inspecting directory %s", argv[2]);
            printInfo(msg);
            checkFolder(dir,argv[2],1,2);
            closedir(dir);
        } else {
            printf("Error: could not open directory\n");
            return 1;
        }
        head=temp;
        checkURL();
        printURL(temp);
        while(temp){
            struct url * t = temp;
            temp=temp->next;
            free(t->domain);
            free(t->file);
            free(t->path);
            free(t);
        }
        free(head);

    }else if(strcmp(argv[1], "monitor") == 0) {
        if(argc != 3) {
            printf("Usage: %s inspect <path>\n", argv[0]);
            return 1;
        }
        printInfo("Application Started");
        snprintf(msg, sizeof(msg), "Monitoring directory %s", argv[2]);
        printInfo(msg);
        signal(SIGINT, sigintHandler);
        monitor(argv[2]);
    }else if(strcmp(argv[1], "slice")==0){
        if(argc != 3) {
            printf("Usage: %s slice <key>\n", argv[0]);
            return 1;
        }
        int key=atoi(argv[2]);
        printInfo("Application Started");
        slice(key);
    }else if(strcmp(argv[1], "unlock")==0){
        if(argc%2!=0) {
            printf("Usage: %s unlock xi yi  ... \n", argv[0]);
            return 1;
        }
        printInfo("Application Started");
        int x1[MAX],y1[MAX],n=0;
        for(int i=2;i<argc;i+=2){
            x1[n]=atoi(argv[i]);
            y1[n]=atoi(argv[i+1]);
            n++;
        }
        if(n<3){
            printf("Error: at least 3 shares\n");
            return 1;
        }
        unlock(x1,y1,n);
    }else if(strcmp(argv[1], "help") == 0) {
        printf("Usage: %s <operation>\n", argv[0]);
        printf("Operations:\n");
        printf("  scan <path> - scan directory for viruses\n");
        printf("  inspect <path> - inspect file for viruses\n");
        printf("  monitor <path> - monitor directory for ransomware\n");
        printf("  slice <key> - generate shares for key\n");
        printf("  unlock <xi> <yi> ... - unlock key\n");
        printf("\n");
        return 0;
    }
    else {
        printf("Error: unknown operation\n");
        return 1;
    }

    return 0;
}


