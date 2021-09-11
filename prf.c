#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
#include "elf64.h"
extern int errno ;
#define SYMTBL_TYPE 2
#define STRTAB_TYPE 3
#define STB_LOCAL 0
#define STB_GLOBAL 1
#define member_size(type, member) sizeof(((type *)0)->member)
#define IS_BREAKPOINT(inst)                 (((inst) >> (8*(sizeof(long) - INT_3_BYTES))) == INT_3)


static Elf64_Ehdr ehdr;
void get_scop_of_function_from_elf(const char *elfFile, unsigned long *addr, const char* func_name);
pid_t run_target(const char *programname);
void run_syscalls_on_function_debugger(pid_t child_pid, unsigned long addr);
int hex_to_int(char c);
int hex_to_ascii(char c, char d);

void get_scop_of_function_from_elf(const char *elfFile, unsigned long *addr, const char* func_name)
{
        int found=0;
        FILE *file = fopen(elfFile, "rb");
        if (file)
        {
                size_t offset_shoff,sec_num_off,addr_sht,entry_size;
                u_int16_t sec_num;
                offset_shoff = (member_size(Elf64_Ehdr, e_ident)) + (member_size(Elf64_Ehdr, e_type)) +
                (member_size(Elf64_Ehdr, e_machine)) + (member_size(Elf64_Ehdr, e_version)) + (member_size(Elf64_Ehdr, e_entry)) + (member_size(Elf64_Ehdr, e_phoff));
                if (fseek(file, offset_shoff, SEEK_SET) != 0)
                        printf("seek error");
                fread(&addr_sht, sizeof(addr_sht), 1, file);
                sec_num_off = offset_shoff + (member_size(Elf64_Ehdr, e_shoff)) + (member_size(Elf64_Ehdr, e_flags)) 
                + (member_size(Elf64_Ehdr, e_ehsize)) +(member_size(Elf64_Ehdr, e_phentsize))
                + (member_size(Elf64_Ehdr, e_phnum))  + (member_size(Elf64_Ehdr, e_shentsize));
                if (fseek(file, sec_num_off, SEEK_SET) != 0)
                        printf("seek error");
                fread(&sec_num, sizeof(sec_num), 1, file);
                if (fseek(file, addr_sht, SEEK_SET) != 0)
                        printf("seek error");

                //look for the symtable in the header 
                size_t size_of_section = sizeof(Elf64_Shdr);
                size_t sym_tbl_entry,sym_tbl_offset,sym_tbl_size,temp,str_tbl_entry,str_tbl_offset,str_tbl_size,func_name_offset_in_str;
                int cou = 0;
                for(int section_i = 0 ; section_i < sec_num; section_i++){
                        u_int32_t cur_type;
                        //read the type of the current section and cheack if it is symtable
                        if (fseek(file, (member_size(Elf64_Shdr, sh_name)), SEEK_CUR) != 0)
                                printf("seek error");
                        
                        fread(&cur_type, (member_size(Elf64_Shdr, sh_type)) , 1, file);
                        if(cur_type == SYMTBL_TYPE ){
                                cou++;
                                //get offset and sym table entry size
                                temp = (member_size(Elf64_Shdr, sh_flags)) +(member_size(Elf64_Shdr, sh_addr));
                                if (fseek(file, temp, SEEK_CUR) != 0)
                                        printf("seek error");
                                fread(&sym_tbl_offset, (member_size(Elf64_Shdr, sh_offset)) , 1, file);
                                fread(&sym_tbl_size, (member_size(Elf64_Shdr, sh_size)) , 1, file);
                                temp = (member_size(Elf64_Shdr, sh_link)) 
                                + (member_size(Elf64_Shdr, sh_info)) +(member_size(Elf64_Shdr, sh_addralign));
                                if (fseek(file, temp, SEEK_CUR) != 0)
                                        printf("seek error");
                                fread(&sym_tbl_entry, sizeof(sym_tbl_entry) , 1, file);
                        }
                        else if(cur_type == STRTAB_TYPE ){
                                cou++;
                                //get offset and str table entry size
                                temp = (member_size(Elf64_Shdr, sh_flags)) +(member_size(Elf64_Shdr, sh_addr));
                                if (fseek(file, temp, SEEK_CUR) != 0)
                                        printf("seek error");
                                fread(&str_tbl_offset, (member_size(Elf64_Shdr, sh_offset)) , 1, file);
                                fread(&str_tbl_size, (member_size(Elf64_Shdr, sh_size)) , 1, file);
                                temp = (member_size(Elf64_Shdr, sh_link))
                                + (member_size(Elf64_Shdr, sh_info)) +(member_size(Elf64_Shdr, sh_addralign));
                                if (fseek(file, temp, SEEK_CUR) != 0)
                                        printf("seek error");
                                fread(&str_tbl_entry, sizeof(str_tbl_entry) , 1, file);
                                //look for the function in str tab
                                if (fseek(file, str_tbl_offset, SEEK_SET) != 0)
                                        printf("seek error");
                                char* curr_name =(char*)malloc(str_tbl_size);
                                for (size_t i = 0; i < str_tbl_size; i++)
                                {
                                        curr_name[i] = 0;
                                }
                                size_t running_index = 0;
                                size_t curr_name_size = 0;
                                while(running_index<str_tbl_size){
                                     u_int8_t curr_letter;
                                     fread(&curr_letter, sizeof(curr_letter) , 1, file); 
                                     if(curr_letter==0){//end of string
                                             char* curr_name2 =(char*)malloc(curr_name_size);
                                             for (size_t i = 0; i < curr_name_size; i++)
                                             {
                                                     curr_name2[i]=curr_name[i];
                                             }
                                             if((curr_name2 != NULL) &&(strcmp(curr_name2,func_name)==0))//check if foo
                                             {
                                                func_name_offset_in_str=running_index-curr_name_size;
                                                free(curr_name2);
                                                break;
                                             }
                                             else{//not foo
                                                curr_name_size = 0;
                                                for (size_t i = 0; i < curr_name_size; i++)
                                                {
                                                     curr_name[i]=0;
                                                }
                                             }
                                             free(curr_name2);
                                     }
                                     else{
                                        curr_name[curr_name_size++] = curr_letter;
                                     }
                                     running_index++;
                                }
                                free(curr_name);
                        }
                        else{//did not find symtab try next section
                                if (fseek(file, addr_sht + section_i*size_of_section, SEEK_SET) != 0)
                                        printf("seek error");
                        }
                }
                if (cou !=2)
                {
                        printf("error could not find symtable or strtab\n");
                }
                //now lets search for func in sytmtbl
                if (fseek(file, sym_tbl_offset, SEEK_SET) != 0)
                        printf("seek error");
                u_int32_t sym_name;
                size_t i=0;
                while(i<sym_tbl_size){
                        fread(&sym_name, sizeof(sym_name) , 1, file);
                        if(sym_name == func_name_offset_in_str){
                                //we found foo, check local/global
                                unsigned char s_inf;
                                fread(&s_inf, sizeof(s_inf) , 1, file);
                                int type = (ELF64_ST_BIND(s_inf));
                                if (type == STB_LOCAL){
                                        printf("PRF:: local found!\n");
                                        exit(0);
                                }
                                else if(type == STB_GLOBAL){
                                        size_t temp2 = (member_size(Elf64_Sym, st_other)) + (member_size(Elf64_Sym, st_shndx));
                                        if (fseek(file, temp2, SEEK_CUR) != 0)
                                                printf("seek error");
                                        size_t func_addr;
                                        fread(&func_addr, sizeof(func_addr) , 1, file);
                                        found=1;
                                        *addr = func_addr;
                                        break;
                                }
                        }
                        else{
                                if (fseek(file, sym_tbl_entry-sizeof(sym_name), SEEK_CUR) != 0)
                                        printf("seek error");
                                i += (sym_tbl_entry);
                        }
                        
                        
                } 
                //could not find the function in the symbol tabel
                if(!found)
                {
                        printf("PRF:: not found!\n");
                        fclose(file);
                        exit(0);
                }
                fclose(file);
        }
}

pid_t run_target(const char *programname)
{
        pid_t pid;
        pid = fork();
        if (pid > 0)
        {
                return pid;
        }
        else if (pid == 0)
        {
                /*Allow tracing of this process*/
                if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
                {
                        perror("ptrace");
                        exit(1);
                }
                /*Replace this process's image with the given program*/
                if(execl(programname, programname, NULL)<0)
                {
                        printf("error");
                }
        }
        else
        {
                //fork error
                perror("fork");
                exit(1);
        }
}

void run_syscalls_on_function_debugger(pid_t child_pid, unsigned long addr)
{
        bool on_foo = false;
        int wait_status;
        struct user_regs_struct regs;
        /*Wait for child to stop on its first instruction*/
        wait(&wait_status);
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        /*Look at the word at the adress we're intreseted in*/
        unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)addr, NULL);
        /*Write the trap instruction 'int 3' into the address*/
        unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
        ptrace(PTRACE_POKETEXT, child_pid, (void *)addr, (void *)data_trap);
        /*Let the child run to the breakpoint and wait for it to reach it*/
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);
        wait(&wait_status); //get to function we want to work on
        if(WIFEXITED(wait_status)){
                        exit(0);
                }
        // find out the return adress of the function we want to work on and add a breakpoint on the return adress
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        unsigned long return_addres = ptrace(PTRACE_PEEKTEXT, child_pid,(regs.rsp), NULL);
        //now put breakpint at return addres
        unsigned long data2 = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)return_addres, NULL);
        unsigned long data2_trap = (data2 & 0xFFFFFFFFFFFFFF00) | 0xCC;
        //add original line of the return of the function back
        ptrace(PTRACE_POKETEXT, child_pid, (void *)return_addres, (void *)data2_trap);
        //add original line of the entrnce of the function back
        ptrace(PTRACE_POKETEXT, child_pid, (void *)addr, (void *)data);
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
        regs.rip -= 1;
        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
        //go back to perform the original line
        /*The child can continue running now from here we want to take care of syscalls*/
        unsigned long cur_syscall_addr = 0;
        while (1)
        { //while still in  function
                /*Enter next system call*/
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                wait(&wait_status);
                if(WIFEXITED(wait_status)){
                        exit(0);
                }
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                if(return_addres == regs.rip-1){
                        //set back original line of return adress
                        ptrace(PTRACE_POKETEXT, child_pid, (void *)return_addres, (void *)data2);
                        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
                        regs.rip -= 1;
                        ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
                        ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
                        run_syscalls_on_function_debugger(child_pid,addr);
                        return;
                }
                ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
                wait(&wait_status);
                ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
                long long error_id = regs.rax;
                cur_syscall_addr= regs.rip -2;
                //need to check if we came from syscall or from breakpoint saying we got to the end of foo
                /*Run system call and stop on exit*/
                if (error_id<0) //syscall failed
                {
                        printf("PRF:: syscall in %lx returned with %lld\n", cur_syscall_addr,error_id);
                }
                /*The child can continue running now*/
        }
}

int main(int argc, char **argv)
{
        pid_t child_pid;
        child_pid = run_target(argv[2]); //0 is the prog name, 1 is the func and 2 is the prog to debug
        unsigned long addr;
        // run specific "debugger"
        get_scop_of_function_from_elf(argv[2], &addr, argv[1]);
        run_syscalls_on_function_debugger(child_pid, addr);
        return 0;
}
