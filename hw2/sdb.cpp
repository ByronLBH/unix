#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <iomanip>
#include <capstone/capstone.h>
#include <vector>
#include <map>
#include <elf.h>
#include <errno.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fstream>

#define NUMBER_TO_DISASM 5



using namespace std;


static csh cshandle = 0;
pid_t pid=0;
string  file_load="";
int size_of_code=0;
char* code=NULL;
int code_size=0;
//////////////////anchor related data
class anchor_item {
public:
    char* anchor_mem;
    unsigned long start;
    unsigned long end;
    unsigned long length;

    // Constructor
    anchor_item(unsigned long start, unsigned long end) : start(start), end(end) {
        length = end - start;
        anchor_mem = nullptr;
    }
};

struct user_regs_struct anchor_regs;
vector<anchor_item> anchor_item_table;


/////////////////functions
void errquit(const char *);
void si();
void cont();
void breakpoint_check();
void breakpoint_set(unsigned long);
void help();
void trap_service_cont(int);
void trap_service_si(int);
bool load(string);
void anchor();
void timetravel();
bool in_range();
int  getcode();
void disasm(unsigned long , int );
/////////////////elf related data
FILE *elf_fp;
Elf64_Ehdr elf_ehdr;      //  ELF header
Elf64_Shdr  elf_str_shdr;  //  string section header
char *elf_str_tab;        //  string tables
Elf64_Shdr elf_text_shdr; //  text section header
/////////////////


////////////////////////////break point related data
typedef struct _breakpoint{
    unsigned long original_code;
    unsigned long address;
}bp;

vector<bp> breakpoint_list;


void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

/////////////////////////anchor function
void anchor() {
    for (anchor_item& mem : anchor_item_table) {
        munmap(mem.anchor_mem, mem.length);
    }
    anchor_item_table.clear();   //清空前一個anchor

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &anchor_regs) < 0) {
        errquit("PTRACE_GETREGS in anchor()");
    }

    char file_path[128];
    snprintf(file_path, sizeof(file_path), "/proc/%u/maps", pid);
    FILE* fp = fopen(file_path, "r");
    if (!fp) {
        cerr << "Error: Failed to open " << file_path << std::endl;
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long mem_start, mem_end;
        char permission[64];
        // cout << line << endl;
        if (sscanf(line, "%lx-%lx %s", &mem_start, &mem_end, permission) == 3) {
            // cout << "hi" << endl;
            if (strstr(permission, "w")) {
                anchor_item mem(mem_start, mem_end);

                mem.anchor_mem = (char*)(mmap(nullptr, mem.length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
                if (mem.anchor_mem == MAP_FAILED) {
                    cerr << "Error: Failed to allocate memory." << endl;
                    continue;
                }

                for (unsigned long i = 0; i < mem.length; i += 8) {
                    errno = 0;
                    long long value = ptrace(PTRACE_PEEKDATA, pid, mem.start + i, nullptr);
                    if (errno != 0) {
                        cerr << "Error: Failed to read memory at address " << hex << mem.start + i << endl;
                        break;
                    }
                    memcpy( mem.anchor_mem + i, &value, sizeof(value));
                }
                anchor_item_table.push_back( mem );
                // Do something with the anchor_item
                // cout << "Memory range [" << hex << mem.start << "-" << mem.end << "] anchored." << endl;
            }
        }
    }
    fclose(fp);
    cout << "** dropped an anchor" << endl;
}

//////////////////////// timetravel

void timetravel() {
    for (int i = 0; i < static_cast<int>(anchor_item_table.size()); i++) {
        unsigned long j;
        unsigned long start = anchor_item_table[i].start;
        unsigned long end = anchor_item_table[i].end;
        for (j = 0; j + start < end; j += 8) {
            long long poke = *reinterpret_cast<long long*>(anchor_item_table[i].anchor_mem + j);
            errno = 0;
            if (ptrace(PTRACE_POKEDATA, pid, reinterpret_cast<void*>(j + start), poke) < 0)
                errquit("ptrace@POKEDATA in timetravel()");
        }
    }

    if (ptrace(PTRACE_SETREGS, pid, nullptr, &anchor_regs) < 0)
        errquit("PTRACE_SETREGS");

    for (int i = 0; i < static_cast<int>(breakpoint_list.size()); i++) {
        if (breakpoint_list[i].address != anchor_regs.rip)
            breakpoint_set(breakpoint_list[i].address);
    }
    cout << "** go back to the anchor point" << endl;
    disasm(anchor_regs.rip, NUMBER_TO_DISASM);
}




void help()
{
    cerr << "- break {instruction-address}: add a break point\n";
    cerr << "- cont: continue execution\n";
    cerr << "- help: show this message\n";
    cerr << "- si: execute a single instruction\n";
    cerr << "- start: start the program and stop at the first instruction\n";
    cerr << "- anchor: set a checkpoint\n";
    cerr << "- timetravel: restore the process status\n";
    cerr << "- exit: terminate the debugger\n";
}


void breakpoint_check(){
     struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
        errquit("Error: Unable to retrieve register values using ptrace(PTRACE_GETREGS)");
    
    for(int i=0;i<static_cast<int>(breakpoint_list.size());i++){
        if(breakpoint_list[i].address!=regs.rip) {
           breakpoint_set(breakpoint_list[i].address);
        //    cout << "hi : " << hex << breakpoint_list[i].address << endl;
        }

    }
}

bool in_range(const unsigned long addr)
{
    return (elf_text_shdr.sh_addr <= addr) && (addr < (elf_text_shdr.sh_addr + elf_text_shdr.sh_size));
    //elf_text_shdr.sh_addr 表示文本段的起始地址，elf_text_shdr.sh_size 表示文本段的大小（字節數
}


int getcode() {
    ifstream file(file_load, ios::binary | ios::ate);
    if (!file.is_open()) {
        cerr << "Failed to open file: " << file_load << endl;
        return -1;
    }
    
    streampos size = file.tellg();  // 獲取檔案大小
    file.seekg(0, ios::beg);  // 將讀取位置移回檔案開頭
    
    code = new char[size];  // 動態分配記憶體
    
    if (!file.read(code, size)) {
        cerr << "Failed to read file: " << file_load << endl;
        delete[] code;  // 釋放記憶體
        return -1;
    }
    
    file.close();  // 關閉檔案
    
    return static_cast<int>(size);  // 返回指令碼的大小
}





void breakpoint_set(unsigned long breakpoint_addr){
    unsigned long orig_code=ptrace(PTRACE_PEEKTEXT,pid,breakpoint_addr,0);
    if((orig_code&0xff)==0xcc){
        // cout<<"breakpoint already exit\n";
        return;
    }else{
        if (ptrace(PTRACE_POKETEXT, pid, breakpoint_addr, (orig_code & 0xffffffffffffff00) | 0xcc) != 0)
            errquit("ptrace(POKETEXT) in breakpoint_set");

        for(int i=0;i<(int)breakpoint_list.size();i++){
            if(breakpoint_list[i].address==breakpoint_addr)   //若已經存在於breakpoint_list 中 則不需要重複加入
               return;
        }

        bp new_bp;
        new_bp.original_code=orig_code;
        new_bp.address=breakpoint_addr;
        breakpoint_list.push_back(new_bp);
        cout << "** set a breakpoint at 0x" << hex << breakpoint_addr << endl;
    }

}


void trap_service_cont(int status)
{
    if (WIFSTOPPED(status))
    {
        if (WSTOPSIG(status) == SIGTRAP)
        {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
                errquit("ptrace(PTRACE_GETREGS) in checkstate");
            for (int i = 0; i < (int)breakpoint_list.size(); i++)  //遍歷斷點列表，找到與 regs.rip - 1（斷點位置）相符的斷點
            {
                if (breakpoint_list[i].address == regs.rip - 1)
                {
                    cout << "** hit a breakpoint at " << hex << breakpoint_list[i].address<<endl;
                    regs.rip--;
                    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0)  //回復原本的內容並且退回去 rip-1段點位置
                        errquit("ptrace(PTRACE_SETREGS) in checkstate");
                    
                    disasm(breakpoint_list[i].address, NUMBER_TO_DISASM);    
                    if (ptrace(PTRACE_POKETEXT, pid, breakpoint_list[i].address, breakpoint_list[i].original_code) != 0)
                        errquit("ptrace(PTRACE_POKETEXT) in checkstate");
                    // regs.rip--;
                    // if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0)  //回復原本的內容並且退回去 rip-1段點位置
                    //     errquit("ptrace(PTRACE_SETREGS) in checkstate");
                    return;

                }
            }
        }else
        {
            cout << "Error: unexcepted condition in trap_service()" << endl;
        }
    }
}





void trap_service_si(int status)
{
    if (WIFSTOPPED(status))
    {
        if (WSTOPSIG(status) == SIGTRAP)
        {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
                errquit("ptrace(PTRACE_GETREGS) in checkstate");
            for (int i = 0; i < (int)breakpoint_list.size(); i++)  //遍歷斷點列表，找到與 regs.rip（斷點位置）相符的斷點
            {
                
                if (breakpoint_list[i].address == regs.rip )  //剛好在breakpoint上 回復就好不須退回
                {
                    cout << "** hit a breakpoint at "<< hex << breakpoint_list[i].address<<endl;
                    if (ptrace(PTRACE_POKETEXT, pid, breakpoint_list[i].address, breakpoint_list[i].original_code) != 0)
                        errquit("ptrace(PTRACE_POKETEXT) ub checkstate");
                }
            }
        }else
        {
            cout << "Error: unexcepted condition in trap_service()" << endl;
        }
    }
}






void disasm(unsigned long dis_addr, int size)
{
    if (!in_range(dis_addr))
    {
        cout << "** the address is out of the range of the text segment\n";
        return;
    }

    if (code == NULL)
        code_size = getcode();
    long long offset = elf_text_shdr.sh_offset + (dis_addr - elf_text_shdr.sh_addr);
    char *cur_code = code + offset;

    csh handle;
    cs_insn *insn;
    size_t count;
    uint64_t cur_addr = (uint64_t)dis_addr;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        errquit("cs_open in disasm");
    if ((count = cs_disasm(handle, (uint8_t *)cur_code, (size_t)code_size, cur_addr, (size_t)size, &insn)) > 0)
    {
        for (int i = 0; i < (int)count; i++)
        {
            unsigned char bytes[16];
            char bits[128] = "";
            memcpy(bytes, insn[i].bytes, insn[i].size);
            for (int j = 0; j < insn[i].size; j++) // bytes to bits
                snprintf(&bits[j * 3], 4, "%2.2x ", bytes[j]);

            if (in_range(insn[i].address))
                cerr << hex << right << setw(12) << insn[i].address << ":  "
                     << left << setw(32) << bits
                     << left << setw(7) << insn[i].mnemonic
                     << left << setw(7) << insn[i].op_str << endl;
            else
            {
                cerr << "** the address is out of the range of the text segment\n";
                break;
            }
        }
        cs_free(insn, count);
    }
    else
        cout << "**   Can not disassemble code!\n";
    cs_close(&handle);
}




void si(){

    breakpoint_check();
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
        errquit("ptrace(PTRACE_SINGLESTEP) in si()");
     
    
    int status;
    if (waitpid(pid, &status, 0) < 0)
        errquit("waitpid in si()");
    if (WIFEXITED(status))
    {
        cout << "** the target program terminated." << endl;
        pid = 0;
        exit(0);
    }else{
        trap_service_si(status);
    }
    
    struct user_regs_struct current_regs;
    if ( ptrace(PTRACE_GETREGS, pid, NULL, &current_regs) < 0)errquit("ptrace(PTRACE_GETREGS) in si()");
    unsigned  long rip =  current_regs.rip;
    disasm(rip,NUMBER_TO_DISASM);
}


void cont()
{
    
    breakpoint_check();
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
        errquit("ptrace(PTRACE_CONT) in cont()");
    
    int status;
    if (waitpid(pid, &status, 0) < 0)
        errquit("waitpid in cont()");
    if (WIFEXITED(status))
    {
        cout << "** the target program terminated." << endl;
        pid = 0;
        exit(0);
    }else{
        trap_service_cont(status);
    }

}



bool load(string file_load){
//    FILE *fp;
   elf_str_tab=NULL;
   int str_shdr_offset;

   if ((elf_fp = fopen(file_load.c_str(), "rb")) == NULL)
        errquit("fopen in load()");

   fread(&(elf_ehdr), 1, sizeof(Elf64_Ehdr), elf_fp);
   
    if (elf_ehdr.e_ident[EI_CLASS] != ELFCLASS64){
        cout<<"Error: not a 64-bit program"<<endl;
        exit(-1);
    }else{
        // Find String Section Header
        str_shdr_offset = elf_ehdr.e_shoff + (elf_ehdr.e_shstrndx) * sizeof(Elf64_Shdr);
        fseek(elf_fp, str_shdr_offset, SEEK_SET);
        fread(&(elf_str_shdr), 1, sizeof(Elf64_Shdr), elf_fp);
        
        // Read String Table
        elf_str_tab = (char *)malloc(1 * elf_str_shdr.sh_size);// 1:size of char 
        fseek(elf_fp, elf_str_shdr.sh_offset, SEEK_SET);
        fread(elf_str_tab, elf_str_shdr.sh_size, 1, elf_fp);
        
        /*  Find Text Section Header    */
        Elf64_Shdr tmp_shdr;
        fseek(elf_fp, elf_ehdr.e_shoff, SEEK_SET);
    
        for (int i = 0; i < elf_ehdr.e_shnum; i++)
        {
            fread(&(tmp_shdr), 1, sizeof(Elf64_Shdr), elf_fp);

            if (strcmp((elf_str_tab + tmp_shdr.sh_name), ".text") == 0)
            {
                elf_text_shdr = tmp_shdr;
                break;
            }

            fseek(elf_fp, elf_ehdr.e_shoff + ((i + 1) * sizeof(Elf64_Shdr)), SEEK_SET);
        }

        
    }
   return 1;
}

int main(int argc,char* argv[]){
    if(argc < 2) {
        fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
        return -1;
    }

    if((pid = fork()) < 0) errquit("fork");

    if(pid == 0) {
        if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
        execvp(argv[1], argv+1);
        errquit("execvp");
    } else  {
        int wait_status;
        string cmd;
        if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
        return -1;
        if(waitpid(pid, &wait_status, 0) < 0) errquit("waitpid");
        ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL);
        file_load=argv[1];
        if(load(file_load)){
          cout<< "** program '" << file_load << "' loaded. entry point 0x" << hex << elf_ehdr.e_entry << endl;
          stringstream ss;
          ss << "0x" << hex << elf_ehdr.e_entry;
          string entry_hex = ss.str();
          unsigned long entry_point=strtoul(entry_hex.c_str(), NULL, 16);
          disasm(entry_point, NUMBER_TO_DISASM);
        }
          

        while(1){
            cout<<"(sdb) ";
            cin>>cmd;
            if(cmd.compare("si")==0){
                si();
            }else if(cmd.compare("cont")==0){
                cont();
            }else if(cmd.compare("break")==0){
                string breakpoint;
                cin>>breakpoint;
                breakpoint_set(strtoul(breakpoint.c_str(), NULL, 16));
            }
            else if(cmd.compare("anchor")==0){
                anchor();
            }else if(cmd.compare("timetravel")==0){
                timetravel();
            }else if(cmd.compare("help")==0){
                help();
            }
            else if ( cmd.compare("quit")==0 ) {
                exit(-1);
            }
        }//while loop
    }//else

    return 0;

}













