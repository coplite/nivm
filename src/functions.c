#include "../include/functions.h"

void register_mov(VM* vMachine){
    uint8_t reg_idx1 = *vMachine->instructionPointer;
    vMachine->instructionPointer++;
    uint8_t reg_idx2 = *vMachine->instructionPointer;
    vMachine->instructionPointer++;
    vMachine->Pop_Storage[reg_idx1] = vMachine->Pop_Storage[reg_idx2];
    return;
}

const char* fn_names[] = {
    "register_mov",
};

void(*FnPtrs[])(VM*) = {
    register_mov,
};
