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
void si();
void trap_service(int);
bool load(string);
void anchor();
void timetravel();
bool in_range();
int getcode();
void disasm(unsigned long , int );
void read_memory_data(anchor_item& );
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

void read_memory_data(anchor_item& mem) {
    unsigned long start = mem.start;
    unsigned long end = mem.end;
    mem.length = end - start;
    void* addr = mmap(NULL, mem.length, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        errquit("Error: Failed to allocate memory.");
    }

    mem.anchor_mem = static_cast<char*>(addr);

    unsigned long i;
    for (i = 0; i + start < end; i += 8) {
        long long value;
        errno = 0;
        value = ptrace(PTRACE_PEEKTEXT, pid, i + start, nullptr);
        if (errno != 0) {
            cerr << "Error: Failed to read memory at address " << hex << i + start << endl;
            break;
        }
        memcpy(mem.anchor_mem + i, &value, sizeof(value));
    }

    if (i == 0) {
        errquit("Error: Failed to read memory data in read_mem_data");
    }
}

void anchor() {
    for (anchor_item& mem : anchor_item_table) {
        munmap(mem.anchor_mem, mem.length);
    }
    anchor_item_table.clear();

    if (ptrace(PTRACE_GETREGS, pid, nullptr, &anchor_regs) < 0) {
        cerr << "Error: Failed to get register information." << endl;
        return;
    }

    char proc_path[128];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/maps", pid);
    FILE* fp = fopen(proc_path, "r");
    if (!fp) {
        cerr << "Error: Failed to open " << proc_path << endl;
        return;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long mem_start, mem_end;
        char permission[64];
        if (sscanf(line, "%lx-%lx %s", &mem_start, &mem_end, permission) == 3) {
            if (strstr(permission, "w")) {
                anchor_item mem(mem_start, mem_end);
                read_memory_data(mem);
                anchor_item_table.push_back(mem);
            }
        }
    }
    cout<< "** dropped an anchor" <<endl;
    fclose(fp);
}

//////////////////////// timetravel


void timetravel() {

    for( int i = 0; i < (int)anchor_item_table.size(); i++ ) {
        // s( anchordata[i] );
        unsigned long j;
        unsigned long start = anchor_item_table[i].start;
        unsigned long end = anchor_item_table[i].end;
        for( j = 0; j + start < end; j += 8) {
            long long poke = *((long long*)(anchor_item_table[i].anchor_mem  + j));
            errno = 0;
            // if( poke > 0)
            //     cout << poke << endl;
            if( ptrace(PTRACE_POKEDATA, pid, (void*)(j + start), poke  ) < 0 )errquit("ptrace@POKEDATA in timetravel()");
        } // for
    } // for


    if ( ptrace(PTRACE_SETREGS, pid, NULL, &anchor_regs) < 0)errquit("PTRACE_SETREGS");

    for( int i = 0; i < (int)breakpoint_list.size(); i++ ) {
        if ( breakpoint_list[i].address != anchor_regs.rip  )
            breakpoint_set( breakpoint_list[i].address);
        // else if( breakptable[i].address == anchor_regs.rip ){
        //     if (ptrace(PTRACE_POKETEXT, pid, breakptable[i].address, breakptable[i].orig_code) != 0)errquit("PTRACE_POKETEXT");
        //     break_addr = breakptable[i].address;
        //     break_addr = anchor_regs.rip;
        // } // else
    } // for

    disasm(anchor_regs.rip,NUMBER_TO_DISASM);
} // timetravel



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
        errquit("ptrace(PTRACE_GETREGS) in breakpoint_check");
    
    for(int i=0;i<int(breakpoint_list.size());i++){
        if(breakpoint_list[i].address>regs.rip)
           breakpoint_set(breakpoint_list[i].address);
    }
}

bool in_range(const unsigned long addr)
{
    // cout << "elf.text_shdr.sh_addr:" << elf.text_shdr.sh_addr << endl;
    // cout << "elf.text_shdr.sh_addr + elf.text_shdr.sh_size:" << elf.text_shdr.sh_addr + elf.text_shdr.sh_size << endl;
    // cout << "addr:" << addr << endl;
    return (elf_text_shdr.sh_addr <= addr) && (addr < (elf_text_shdr.sh_addr + elf_text_shdr.sh_size));
}


int getcode()
{
    ifstream f(file_load.c_str(), ios::in | ios::binary);
    f.seekg(0, f.end);
    int size = f.tellg();
    f.seekg(0, f.beg);
    code = (char *)malloc(sizeof(char) * size);
    f.read(code, size);
    f.close();
    return size;
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


void trap_service(int status)
{
    // int status;
    // if (waitpid(pid, &status, 0) < 0)
    //     errquit("waitpid in checkstate");
    // if (WIFEXITED(status))
    // {
    //     cout << "** the target program terminated." << endl;
    //     pid = 0;
    //     exit(0);
    // }
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
                    cout << "** breakpoint @ " << hex << breakpoint_list[i].address<<endl;
                    disasm(breakpoint_list[i].address, NUMBER_TO_DISASM);    
                    if (ptrace(PTRACE_POKETEXT, pid, breakpoint_list[i].address, breakpoint_list[i].original_code) != 0)
                        errquit("ptrace(PTRACE_POKETEXT) in checkstate");
                    regs.rip--;
                    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0)  //回復原本的內容並且退回去 rip-1段點位置
                        errquit("ptrace(PTRACE_SETREGS) in checkstate");
                }
                else if (breakpoint_list[i].address == regs.rip)  //若剛好在breakpoint上 回復就好不須退回
                {
                    cout << "** breakpoint @ "<< hex << breakpoint_list[i].address<<endl;
                    disasm(breakpoint_list[i].address, NUMBER_TO_DISASM);
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
        trap_service(status);
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
        trap_service(status);
    }

}



bool load(string file_load){
//    FILE *fp;
   elf_str_tab=NULL;
   int str_shdr_offset;

   if ((elf_fp = fopen(file_load.c_str(), "rb")) == NULL)
        errquit("fopen in load()");
//    elf_fp = fp;

   fread(&(elf_ehdr), 1, sizeof(Elf64_Ehdr), elf_fp);
   if (elf_ehdr.e_ident[EI_MAG0] == 0x7f &&
        elf_ehdr.e_ident[EI_MAG1] == 'E' &&
        elf_ehdr.e_ident[EI_MAG2] == 'L' &&
        elf_ehdr.e_ident[EI_MAG3] == 'F')
   {
        if (elf_ehdr.e_ident[EI_CLASS] != ELFCLASS64){
            cout<<"Error: not a 64-bit program"<<endl;
            exit(-1);
        }else{
            /*  Find String Section Header  */
            /*  section header table's file offset + section header table index of the string table * section header size   */
            str_shdr_offset = elf_ehdr.e_shoff + (elf_ehdr.e_shstrndx) * sizeof(Elf64_Shdr);
            fseek(elf_fp, str_shdr_offset, SEEK_SET);
            fread(&(elf_str_shdr), 1, sizeof(Elf64_Shdr), elf_fp);
            elf_str_tab = (char *)malloc(sizeof(char) * elf_str_shdr.sh_size);
            fseek(elf_fp, elf_str_shdr.sh_offset, SEEK_SET);
            fread(elf_str_tab, elf_str_shdr.sh_size, sizeof(char), elf_fp);
           
            /*  Find Text Section Header    */
            Elf64_Shdr tmp_shdr;
            fseek(elf_fp, elf_ehdr.e_shoff, SEEK_SET);
            for (int i = 0; i < elf_ehdr.e_shnum; i++)
            {
                fread(&(tmp_shdr), 1, sizeof(Elf64_Shdr), elf_fp);
                if (strcmp((elf_str_tab + tmp_shdr.sh_name), ".text") == 0)
                {
                    elf_text_shdr = tmp_shdr;
                   
                }
            }
            
        }
   }//if
   else{
     cout<<"Error:fail to find ELF file"<<endl;
     exit(-1);
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
        }//while loop
    }//else

    return 0;

}