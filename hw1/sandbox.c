#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h> 
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>//getaddrinfo
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h> // bool
#include <elf.h>
#include <dlfcn.h> // dlopen dlclose
#include <sys/mman.h> // mmprotect
#include <unistd.h> // _SC_PAGE_SIZE
#include <sys/stat.h>

static int global_fd = -1;
const char *global_node;
extern int errno;
static char* filter = NULL;  

int getindex( FILE* ElfFile, char* sect_name, Elf64_Ehdr elfHdr  ){
    Elf64_Shdr sectHdr;
    fseek(ElfFile, elfHdr.e_shoff + elfHdr.e_shstrndx * sizeof(sectHdr), SEEK_SET);
    fread(&sectHdr, sizeof(sectHdr), 1, ElfFile);
    char *SectNames=NULL;
    SectNames = malloc(sectHdr.sh_size);
    fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
    fread(SectNames, sectHdr.sh_size, 1, ElfFile);
    for (int idx = 0; idx < elfHdr.e_shnum; idx++)
    {
        fseek(ElfFile, elfHdr.e_shoff + idx * sizeof(sectHdr), SEEK_SET);
        fread(&sectHdr, sizeof(sectHdr), 1, ElfFile);

        // print section name
        const char *name = "";
        name = SectNames + sectHdr.sh_name;
        // if(idx>0) printf("sectname: %s , name: %u\n",SectNames,sectHdr.sh_name);

        if (strcmp(name, sect_name)==0) {
            return idx;
        }

        // printf("%2u %s\n", idx, name);
    }
} // getindex




bool check_blacklist(const char* filename,const char* API_name,void *content, ssize_t read_len){
    FILE *fp=NULL;
    char *line = NULL;
    size_t len = 0; 
    ssize_t read; 
    
    // char *config_path = getenv("SANDBOX_CONFIG");
    // printf("get argv: %s\n",config_path);

    fp = fopen(getenv("SANDBOX_CONFIG"),"r");
    if(fp==NULL){
        printf("error: can not getenv SANDBOX_CONFIG in check_blacklist\n");
    }
    // printf("enter check_blacklist\n");

    bool begin_of_blacklist=false;
    bool result=false;
    char* clear;
    while((read=getline(&line,&len,fp))!=-1){
        if (strstr(line, "BEGIN") != NULL && strstr(line, API_name) != NULL) {
            begin_of_blacklist = true;
        }
        else if( begin_of_blacklist && strstr(line, API_name) != NULL && strstr(line, "END") != NULL ) {
            return false;
        } // if
        else if(begin_of_blacklist){
            if(strstr(line, "\n") ) {
                // printf("clear n in line: %s",line);
                // *clear = '\0';
                int line_len=strlen(line);
                if(line_len>0){
                    line[line_len-1]='\0';
                }
            } // if
            if(API_name=="open"){
                char abs_path[1024] = "";
                realpath(line, abs_path);
                if(strstr(filename, abs_path) != NULL){
                   return true;
                }
            } else if(API_name=="read"){
                if(strstr(content , line)) return true;
            } else if(API_name=="getaddrinfo" || API_name == "connect"){
                if(strstr(line, filename)) return true;
            }

        }     

    }
    free(line);
    fclose(fp);
    free(fp);

    return result;

}




int open_h(const char *pathname, int flags, ...) {
    va_list args;     //varilable argument
    mode_t mode = 0;  //default value
    // printf("enter open_h\n");
    
    //record the real open() in clib
    void *handle=NULL;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    if(handle==NULL){
        printf("dlsym error in open_h\n");
        return -1;
    }
    int (*orig_open)(const char *, int, ...) = NULL;
    orig_open = dlsym(handle, "open");
    if (orig_open == NULL) {
        printf("dlsym error in open_h\n");
        dlclose(handle);
        return -1;
    }
    dlclose(handle);
    //
    
    va_start(args, flags); //initilize 
    mode = va_arg(args, int);
    va_end(args);   // clear args
    

    if (check_blacklist(pathname,"open",NULL,0)==true){
        errno = EACCES;
        dprintf(global_fd, "[logger] open(\"%s\", %d, %d) = %d\n", pathname, flags, mode,-1);
        return -1;
    }
    //call real open in libc according to number of arguments
    int orig_return;
    if (mode!=0)
        orig_return = orig_open(pathname, flags, mode);
    else
        orig_return = orig_open(pathname, flags);

    if( orig_return != -1)
        filter = NULL;   

    dprintf(global_fd, "[logger] open(\"%s\", %d, %d) = %d\n", pathname, flags, mode, orig_return);

    // printf("finish open_h\n");
    return orig_return;
} 



ssize_t read_h(int fd, void* buf,size_t len){
    void* handle=dlopen("libc.so.6",RTLD_LAZY);
    if(handle==NULL){
        printf("dlsym error in read_h\n");
        return -1;
    }
    
    ssize_t  (*orig_read)(int, void*, size_t)=dlsym(handle, "read");
    if (orig_read == NULL) {
        printf("dlsym error in read_h\n");
        dlclose(handle);
        return -1;
    }
    dlclose(handle);
    ssize_t orig_return = orig_read(fd, buf, len);

    if (check_blacklist("","read",buf,orig_return)) {
        errno = EIO;
        dprintf(global_fd, "[logger] read(%d, %p, %ld) = -1\n", fd, buf, len);
        close(fd);
        dlclose(handle);
        return -1;
    }
    
    FILE *file = NULL;
    char filename[50];
    snprintf(filename, sizeof(filename), "%d-%d-read.log", getpid(), fd);
    file = fopen(filename, "a");
    if (file == NULL) {
        printf("fopen error in read_h\n");
        dlclose(handle);
        return -1;
    }
    fwrite(buf, sizeof(char), orig_return, file);
    fclose(file);

   

    // return the original return from read() in libc
    dprintf(global_fd, "[logger] read(%d, %p, %ld) = %ld\n", fd, buf, len, orig_return);
    return orig_return;

}

ssize_t write_h( int fd, const void *buf, size_t count) {
    void *handle=NULL;
    handle = dlopen("libc.so.6",RTLD_LAZY); 
    if(handle==NULL){
        printf("dlsym error in write_h\n");
        return -1;
    }

    ssize_t (*orig_write)(int ,const void*,size_t) = NULL;
    orig_write = dlsym(handle, "write");
    if(orig_write==NULL){
        printf("dlsym error in read_h\n");
        dlclose(handle);
        return -1;
    }
    dlclose(handle);
    
    FILE *file=NULL;
    char filename[256] = "";
    sprintf(filename, "%ld-%d-write.log", (long)getpid(), fd);
    file = fopen(filename, "a");
    if(file==NULL){
        printf("fail to fopen in write_h\n");
    }

    ssize_t orig_return;
    orig_return = orig_write(fd ,buf, count);
    fwrite( buf,sizeof(char), orig_return,file);
    fclose(file);

    dprintf(global_fd,  "[logger] write(%d, %p, %ld) = %ld\n", fd, buf, count, orig_return);
    return orig_return;
} 



int connect_h(int sockfd,const struct sockaddr_in* addr,socklen_t addrlen){
    int (*orig_connect)(int, const struct sockaddr_in *, socklen_t)=NULL;
    void *handle = dlopen("libc.so.6", RTLD_LAZY);
    if(handle==NULL){
        printf("dlsym error in connect_h\n");
        return -1;
    }
    
    orig_connect=dlsym(handle,"connect");
    if(orig_connect==NULL){
        printf("dlsym error in read_h\n");
        dlclose(handle);
        return -1;
    }
    dlclose(handle);
    
    char ip[INET_ADDRSTRLEN];
    inet_ntop( addr->sin_family, &addr->sin_addr, ip, sizeof(ip));

    char addr_name[128] = "";
    int port = ntohs(addr->sin_port);
    snprintf(addr_name, 128, "%s:%d", global_node, port);  

     if (check_blacklist(addr_name,"connect",NULL,0)) {
        errno = ECONNREFUSED;
        dprintf(global_fd, "[logger] connect(%d, \"%s\", %d) = -1\n", sockfd, ip, addrlen);
        return -1;
    }
    int orig_return=orig_connect(sockfd, addr, addrlen);
    dprintf(global_fd, "[logger] connect(%d, \"%s\", %d) = %d\n", sockfd, ip, addrlen, orig_return);
    return orig_return;
}


int system_h(const char* command){
    void *handle=NULL;
    handle=dlopen("libc.so.6",RTLD_LAZY);
    if(handle==NULL){
        printf("dlsym error in  system_h\n");
        return -1;
    }
    
    int (*orig_system)(const char*)=NULL;
    orig_system=dlsym(handle,"system");
    if(orig_system==NULL){
        printf("dlsym error in read_h\n");
        dlclose(handle);
        return -1;
    }
    dlclose(handle);
    
    if(command==NULL) return 1;
    dprintf(global_fd,  "[logger] system(\"%s\")", command);


    int orig_return=orig_system(command);
    return orig_return;
}




int getaddrinfo_h(const char *restrict node,const char *restrict service,const struct addrinfo *restrict hints,
                struct addrinfo **restrict res){
    

    void *handle=NULL;
    handle = dlopen("libc.so.6", RTLD_LAZY);
    if(handle==NULL){
        printf("dlsym error in  getaddrinfo_h\n");
        return -1;
    }

    int (*orig_getaddrinfo)(const char *restrict, const char *restrict,const struct addrinfo *restrict,struct addrinfo **restrict) = NULL;
    orig_getaddrinfo=dlsym(handle,"getaddrinfo");

    if(orig_getaddrinfo==NULL){
        printf("dlsym error in read_h\n");
        dlclose(handle);
        return -1;
    }
    dlclose(handle);

    global_node = node;
    if(check_blacklist(node,"getaddrinfo",NULL,0)){
        dprintf(global_fd,  "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %d\n", node, service, hints, res, EAI_NONAME);
        return EAI_NONAME;
    }

    int orig_return;
    orig_return = orig_getaddrinfo( node, service, hints, res);

    dprintf(global_fd,  "[logger] getaddrinfo(\"%s\",\"%s\",%p,%p) = %d\n", node, service, hints, res,orig_return);
    return orig_return;
    

}



void got_func( char* filename, long base ) {
    FILE *ElfFile;
    ElfFile = fopen("/proc/self/exe", "rb");
    if (!ElfFile)
    {
        fprintf(stderr, "error: unable to open elf file\n");
        exit(1);
    }
    //https://stackoverflow.com/questions/70583281/print-the-names-of-the-sections-headers-of-an-elf-file
    //https://stackoverflow.com/questions/29052125/reading-the-contents-of-an-elf-sectionprogrammatically
    Elf64_Ehdr elfHdr;
    Elf64_Shdr sectHdr;

    fread(&elfHdr, sizeof(elfHdr), 1, ElfFile);

    // find section name
    
    // fseek(ElfFile, elfHdr.e_shoff + elfHdr.e_shstrndx * elfHdr.e_shentsize, SEEK_SET);
    // fread(&sectHdr, elfHdr.e_shentsize, 1, ElfFile);
    // char *SectNames=NULL;
    // SectNames = malloc(sectHdr.sh_size);
    // fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
    // fread(SectNames, sectHdr.sh_size, 1, ElfFile);
    //////////////////////////
    int rela_plt_idx;
    int dynsym_idx;
    // read all section headers, find .rela.plt

     
    // find symbol name in .dynsym
    dynsym_idx = getindex(ElfFile,".dynsym",elfHdr);
    fseek(ElfFile, elfHdr.e_shoff + dynsym_idx * elfHdr.e_shentsize, SEEK_SET);
    fread(&sectHdr, elfHdr.e_shentsize, 1, ElfFile);
    Elf64_Sym *symNamesTable=NULL;
    symNamesTable = malloc(sectHdr.sh_size);
    fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
    int entry_num=sectHdr.sh_size / sizeof(Elf64_Sym);
    fread(symNamesTable, sizeof(Elf64_Sym),entry_num, ElfFile);

    // find symbol names in .dynstr
    fseek(ElfFile, elfHdr.e_shoff + sectHdr.sh_link * elfHdr.e_shentsize, SEEK_SET);
    fread(&sectHdr, elfHdr.e_shentsize, 1, ElfFile);
    char *strSymNames=NULL;
    strSymNames = malloc(sectHdr.sh_size);
    fseek(ElfFile, sectHdr.sh_offset, SEEK_SET);
    fread(strSymNames, sectHdr.sh_size, 1, ElfFile);
    //////////////////////////
    // printf("strSymNames: %s\n",strSymNames);
    
    // find got offset in rela
    rela_plt_idx = getindex(ElfFile,".rela.plt",elfHdr);
    fseek(ElfFile, elfHdr.e_shoff + rela_plt_idx * elfHdr.e_shentsize, SEEK_SET);
    fread(&sectHdr, elfHdr.e_shentsize, 1, ElfFile);
    Elf64_Rela rela;
    // printf("dynsym_idx: %d , rela_plt_idx: %d\n", dynsym_idx, rela_plt_idx);

    long func_addr;
    for (int idx = 0; idx < (sectHdr.sh_size / sizeof(rela)); idx++)
    {
        
        //get the addr from (offset+the index in section header*sezeof each entry in section header)
        fseek(ElfFile, sectHdr.sh_offset + idx * sizeof(rela), SEEK_SET);
        fread(&rela, sizeof(rela), 1, ElfFile);

        const char *name = "";
        name = strSymNames + symNamesTable[ELF64_R_SYM(rela.r_info)].st_name;
        
        func_addr = base + rela.r_offset;
        
        // printf("%2u %s\n", idx, name);
        API_hijaction(func_addr,name);
    }

    fclose(ElfFile);

} // got_func



void API_hijaction(long func_addr,const char* API_name){
    // page size:4096 , calculate the page that the program located at
    // printf("page size: %ld\n",  sysconf(_SC_PAGE_SIZE));
    int  pagesize = sysconf(_SC_PAGE_SIZE); 
    long starting_page=func_addr/pagesize*pagesize ;
    
    if(strcmp(API_name, "open")==0){
        if(mprotect(starting_page,pagesize,PROT_READ | PROT_WRITE) !=-1){
            int (*open_ptr)(const char* ,int , ...)=&open_h;
            void *func_ptr=(void*)open_ptr;
            memcpy((void*) func_addr,&func_ptr,8);
        }else{
            printf("error: unable to hijact %s", API_name);
        }
    }else if(strcmp(API_name, "read")==0){
         if(mprotect(starting_page,pagesize,PROT_READ | PROT_WRITE) !=-1){
            int (*open_ptr)(int, void*, size_t)=&read_h;
            void *func_ptr=(void*)open_ptr;
            memcpy((void*) func_addr,&func_ptr,8);
        }else{
            printf("error: unable to hijact %s", API_name);
        } 
    }else if(strcmp(API_name, "write")==0){
         if(mprotect(starting_page,pagesize,PROT_READ | PROT_WRITE) !=-1){
            int (*open_ptr)(int, const void*, size_t)=&write_h;
            void *func_ptr=(void*)open_ptr;
            memcpy((void*) func_addr,&func_ptr,8);
        }else{
            printf("error: unable to hijact %s", API_name);
        } 
    }else if(!strcmp(API_name, "connect")){
         if(mprotect(starting_page,pagesize,PROT_READ | PROT_WRITE) !=-1){
            int (*open_ptr)(int, const struct sockaddr*, socklen_t)=&connect_h;
            void *func_ptr=(void*)open_ptr;
            memcpy((void*) func_addr,&func_ptr,8);
        }else{
            printf("error: unable to hijact %s", API_name);
        } 
    }else if(strcmp(API_name, "getaddrinfo")==0){
         if(mprotect(starting_page,pagesize,PROT_READ | PROT_WRITE) !=-1){
            int (*open_ptr)(const char*, const char*, const struct addrinfo*, struct addrinfo**)=&getaddrinfo_h;
            void *func_ptr=(void*)open_ptr;
            memcpy((void*) func_addr,&func_ptr,8);
        }else{
            printf("error: unable to hijact %s", API_name);
        } 
    }else if(strcmp(API_name, "system")==0){
         if(mprotect(starting_page,pagesize,PROT_READ | PROT_WRITE) !=-1){
            int (*open_ptr)(const char*)=&system_h;
            void *func_ptr=(void*)open_ptr;
            memcpy((void*) func_addr,&func_ptr,8);
        }else{
            printf("error: unable to hijact %s", API_name);
        } 
    }
}


int __libc_start_main( int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), 
                        void (*fini) (void), void (*rtld_fini) (void), void (*stack_end) ) {

    typedef void (*func_ptr)(void);
    int (*orig_func)(void *, int, char *[], func_ptr, func_ptr, func_ptr, void*)=NULL;
    

    // store the original __libc_start_main for later return
    void *handle;
    if(orig_func==NULL){
       handle = dlopen("libc.so.6",RTLD_LAZY); 
       if(handle!=NULL)
          orig_func =  dlsym( handle, "__libc_start_main");
    }
    dlclose(handle); 
    

    char file_to_open[]="/proc/self/maps";
    FILE *fp;
    char *line=NULL;
    size_t len=0;
    ssize_t read;
    fp=fopen(file_to_open,"r");
    if(fp==NULL){
        printf("error: unable to open %s",file_to_open);
        exit(1);
    }
    
    static long main_min = 0, main_max = 0;
    bool addr_get = false ;
    char cmd[32];
    
    //https://blog.csdn.net/zqixiao_09/article/details/50253883
    // main_min: base addr of main

    //parse the /proc/self/maps of the running program , the address of the executable lies in the first line 
    while ((read = getline(&line, &len, fp) != -1 ) ) {
        if (!addr_get)  {  
            sscanf(line, "%lx-%lx %*s %*s %*s %*s %s", &main_min, &main_max,cmd);
        } 
        //printf("%s",line);
        addr_get=true;
    } 
    fclose(fp);
    //fflush(stdout);



    got_func( cmd, main_min );
    sscanf(getenv("LOGGER_FD"),"%d",&global_fd); //record the logger fd
    return orig_func( main, argc, ubp_av, init, fini, rtld_fini, stack_end );

} 
