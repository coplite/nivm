#include "../include/common.h"
#include "../include/vm.h"
#include "../include/instr.h"
#include "../include/debug.h"

int main(int argc, char** argv){

    VM VirtualMachine   = {0};
    OpArray code        = {0};

    init_vm(&VirtualMachine);
    init_instructions(&code);

    /*
    Value val = {
        .value_type = TYPE_STR,
        .as.type_str = create_string("Hello World!", 12, &VirtualMachine.head),
    };
    uint32_t constant = add_constant(&code, val);
    write_instruction(&code, OP_CONST);
    write_operands(&code, constant, sizeof(int32_t));

    write_instruction(&code, OP_NOP);

    val.value_type = TYPE_INT;
    val.as.type_int = 2;
    constant = add_constant(&code, val);
    write_instruction(&code, OP_CALL);
    write_operands(&code, 2, sizeof(int32_t));

    write_instruction(&code, OP_PRINT);
    write_instruction(&code, OP_EXIT);

    val.value_type = TYPE_STR;
    val.as.type_str = create_string("daikirai", 8, &VirtualMachine.head);
    constant = add_constant(&code, val);
    write_instruction(&code, OP_CONST);
    write_operands(&code, constant, sizeof(int32_t));

    val.as.type_str = create_string(" is my cute", 11, &VirtualMachine.head);
    constant = add_constant(&code, val);
    write_instruction(&code, OP_CONST);
    write_operands(&code, constant, sizeof(int32_t));

    write_instruction(&code, OP_CONCAT);

    val.as.type_str = create_string(" patooie", 8, &VirtualMachine.head);
    constant = add_constant(&code, val);
    write_instruction(&code, OP_CONST);
    write_operands(&code, constant, sizeof(int32_t));

    write_instruction(&code, OP_CONCAT);

    val.as.type_str = create_string("daikirai is my cute patooie", 27, &VirtualMachine.head);
    constant = add_constant(&code, val);
    write_instruction(&code, OP_CONST);
    write_operands(&code, constant, sizeof(int32_t));

    write_instruction(&code, OP_STRING_EQUAL);

    Value val2 = {
        .value_type = TYPE_FLT,
        .as.type_flt = 3.1,
    };
    constant = add_constant(&code, val2);
    write_instruction(&code, OP_JUMP_IF_TRUE);
    write_operands(&code, 3, sizeof(int32_t));

    write_instruction(&code, OP_RETURN);

    write_instruction(&code, OP_NOP);

    write_instruction(&code, OP_NOP);

    val2.value_type = TYPE_STR;
    val2.as.type_str = create_string("I the SnickerDoodle has awakened!", 33, &VirtualMachine.head);
    constant = add_constant(&code, val2);
    write_instruction(&code, OP_CONST);
    write_operands(&code, constant, sizeof(int32_t));

    write_instruction(&code, OP_PRINT);

    write_instruction(&code, OP_RETURN);
    */

    

    /*
    Value val = {
        .value_type = TYPE_STR,
        .as.type_str = create_string("Hello World!", 12, &VirtualMachine.head),
    };
    uint32_t const_idx = add_constant(&code, val);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 0, sizeof(uint8_t));

    write_instruction(&code, OP_EVAL);
    write_operands(&code, 0, sizeof(uint8_t));  // fn idx
    write_operands(&code, 1, sizeof(uint8_t));  // operand to fn poitner
    write_operands(&code, 0, sizeof(uint8_t));

    write_instruction(&code, OP_PUSH_REGISTER);
    write_operands(&code, 1, sizeof(uint8_t));
    
    write_instruction(&code, OP_PRINT);
    write_instruction(&code, OP_EXIT);
    disassemble_array(&code, "Instruction Parcel", &VirtualMachine);
    //getchar();
    */

    Value SSN = {
        .value_type = TYPE_INT,
        .as.type_int = 0x2000005,       // open()
    };
    uint32_t const_idx = add_constant(&code, SSN);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));

    Value arg1 = {
        .value_type = TYPE_STR,
        .as.type_str = create_string("gamaggut.txt", 12, &VirtualMachine.head),
    };

    const_idx = add_constant(&code, arg1);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));

    Value arg2 = {
        .value_type = TYPE_INT,
        .as.type_int = O_RDWR | O_CREAT | O_TRUNC,
    };
    const_idx = add_constant(&code, arg2);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));

    Value arg3 = {
        .value_type = TYPE_INT,
        .as.type_int = 438,     /// 666 in octal
    };
    const_idx = add_constant(&code, arg3);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 3, sizeof(uint8_t));

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 2, sizeof(uint8_t));

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 1, sizeof(uint8_t));

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 0, sizeof(uint8_t));

    write_instruction(&code, OP_SYSCALL);

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 1, sizeof(uint8_t));

    write_instruction(&code, OP_EVAL);
    write_operands(&code, 0, sizeof(uint8_t));
    write_operands(&code, 10, sizeof(uint8_t));
    write_operands(&code, 1, sizeof(uint8_t));

    SSN.as.type_int = 0x200004; // write()
    const_idx = add_constant(&code, SSN);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));

    arg2.value_type = TYPE_STR;
    arg2.as.type_str = create_string("Hxxy xxx yxxduck!!\n", 19, &VirtualMachine.head);
    const_idx = add_constant(&code, arg2);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));

    arg3.value_type = TYPE_INT;
    arg3.as.type_int = arg2.as.type_str->size;
    const_idx = add_constant(&code, arg3);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 3, sizeof(uint8_t));

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 2, sizeof(uint8_t));

    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 0, sizeof(uint8_t));

    write_instruction(&code, OP_SYSCALL);


    SSN.as.type_int = 0x2000006;    // close
    const_idx = add_constant(&code, SSN);
    write_instruction(&code, OP_CONST);
    write_operands(&code, const_idx, sizeof(uint32_t));
    
    write_instruction(&code, OP_POP_REGISTER);
    write_operands(&code, 0, sizeof(uint8_t));

    write_instruction(&code, OP_EVAL);
    write_operands(&code, 0, sizeof(uint8_t));
    write_operands(&code, 1, sizeof(uint8_t));
    write_operands(&code, 10, sizeof(uint8_t));

    write_instruction(&code, OP_SYSCALL);

    write_instruction(&code, OP_EXIT);
    disassemble_array(&code, "Instruction Parcel", &VirtualMachine);

    /*

            [IN COMMON.H HEADER FILE]

    typedef NTSTATUS (NTAPI *NtCreateThread_t)(
        OUT PHANDLE ThreadHandle,
        IN ACCESS_MASK DesiredAccess,
        IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
        IN HANDLE ProcessHandle,
        OUT PCLIENT_ID ClientId,
        IN PCONTEXT ThreadContext,
        IN PINITIAL_TEB InitialTeb,
        IN BOOLEAN CreateSuspended
    );

    typedef NTSTATUS (NTAPI *NtDelayExecution_t)(
        IN BOOLEAN Alertable,
        IN PLARGE_INTEGER DelayInterval
    );

    typedef NTSTATUS (NTAPI *NtContinue_t)(
        IN PCONTEXT ThreadContext,
        IN BOOLEAN RaiseAlert
    );

    typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
        IN HANDLE ProcessHandle,
        IN PVOID BaseAddress,
        IN PVOID Buffer,
        IN ULONG NumberOfBytesToWrite,
        OUT PULONG NumberOfBytesWritten OPTIONAL
    );

    // Union of Nt function pointers
    typedef union _NtFunctionUnion {
        NtCreateThread_t          NtCreateThread;
        NtDelayExecution_t        NtDelayExecution;
        NtContinue_t              NtContinue;
        NtWriteVirtualMemory_t    NtWriteVirtualMemory;
    } NtFunctionUnion;

            [IN MAIN.C MAIN FUNCTION]

    Value val = {
        .value_type = TYPE_STR,
        .as.type_str = create_string("{SHELLCODE_IMPLANT}", sizeof(implant) - 1),
    }; 
    int constImplant = add_constant(&code, val);
    val = {
        .value_type = TYPE_INT,
        .as.type_int = getSSN("NtCreateProcess");
    }; 
    int constSSN = add_constant(&code, val);
    val = {
        .value_type = TYPE_PTR,     UINT_PTR
        .as.type_ptr = (UINT_PTR)GetProcAddress(GetModuleHandleA("ntdll.dll") , "NtCreateProcess") + 0x12,
    }; 
    int constJMP = add_constant(&code, val);

    Note on the * in the comment
    
    LARGE_INTEGER interval;
    interval.QuadPart = -10000000LL;
    val = {
        .VALUE_TYPE = TYPE_LARGE_INT,
        .as.type_large_int = interval,
    }; 
    int arg2 = add_constant(&code, val);
    val = {
        .VALUE_TYPE = TYPE_BOOL,
        .as.type_bool = false,
    };
   int arg1 = add_constant(&code, val); 


    write_instruction(&code, OP_CONST)
    write_instruction(&code, arg2);

    write_instruction(&code, OP_CONST)
    write_instruction(&code, arg1);
    
    write_instruction(&code, OP_CONST)
    write_instruction(&code, constJMP);

    write_instruction(&code, OP_CONST)
    write_instruction(&code, constSSN);

    write_instruction(&code, OP_NT_CALL);
    write_instruction(&code, 2);

    interpret(Virtual_Machine, &code);


    IDEA:   array of Values that are stored after the pop
            and based on the SSN we resolve the NT fn name
            which pushes its ret val onto the stack then pop 
            the retvalue to the register then set up the stack
            again and call the value


                    [IN VM.C]

    case OP_NT_CALL:{
        Value SSN = pop(vMachine);      // DWORD
        --> check if valid then set 
            the global extern var to SSN.as.DWORD
        Value NtSyscallJump = pop(vMachine);    // uintptr_t
         --> check if valid then set 
            the global extern var to SSN.as.UINTPTR
        int N = *vMachine->instructionPointer;
        vMachine->instructionPointer++;
        Value args[N];
        memset(args, 0, N);
        for(int i = 0; i < N; i++){
            args[i] = pop(vMachine);
        }
        NtFunctionUnion ntFunc;
        const char* syscallFunction = get_fn_from_ssn(SSN.as.DWORD);
        int api_hash = f1nva(syscallFunction);
        switch(api_hash){
            case 0x00544e304:{      // hash for NtDelayExecution
                ntFunc.NtDelayExecution_t = (NtDelayExecution_t)GetProcAddress(hNtdll, "NtDelayExecution");
                if(!ntFunc.NtDelayExecution_t){
                    throw_error(vMachine, "OP_NT_CALL", "Unable to resolve NtFunction Syscall")
                    return VM_NAY
                }
*               ntFunc.NtDelayExecution_t(args[0].as.type_bool, &args[1].as.type_large_int)
                //-->    store the modified param in Pop_Storage in case of function calls like NtVirtualAlloc
                        that update their buffer value
            }
        }
    }


    NtFunc()
    */
    puts("================ Starting VM ================");
    interpret(&VirtualMachine, &code);
    free_vm(&VirtualMachine);
    free_instructions(&code);
    return 0;
}

// clang -Wno-error=gnu-label-as-value -Werror -Wall -pedantic main.c instr.c vm.c gc.c functions.c  debug.c -O2 -o VMI && ./VMI
// clang -Wno-error=gnu-label-as-value -Werror -Wall -pedantic main.c instr.c vm.c gc.c functions.c  debug.c -Os -o VMI && ./VMI
