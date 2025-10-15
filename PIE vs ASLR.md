# สถานการณ์ทั้งหมดของ PIE และ ASLR

## เมทริกซ์แสดงทุกกรณี (2×2)

| | **ไม่มี ASLR** | **มี ASLR** |
|---|---|---|
| **ไม่มี PIE** | Case 1 | Case 2 |
| **มี PIE** | Case 3 | Case 4 |

---

## Case 1: ไม่มี PIE, ไม่มี ASLR ❌❌

### Memory Layout
```
Executable:  0x0000000000400000  (fixed)
.text:       0x0000000000400400  (fixed)
.data:       0x0000000000601000  (fixed)
.bss:        0x0000000000602000  (fixed)

libc:        0x00007ffff7a0d000  (fixed)
system():    0x00007ffff7a52390  (fixed)
printf():    0x00007ffff7a62800  (fixed)

stack:       0x00007ffffffde000  (fixed)
heap:        0x0000000000603000  (fixed)
```

### ลักษณะ
- 🎯 **ทุก address คาดเดาได้ 100%**
- 🎯 **รันกี่ครั้งก็ address เดิม**
- 🎯 **Exploit ง่ายที่สุด**

### ตัวอย่างการโจมตี
```python
# ROP chain สามารถเขียน hardcode ได้เลย
payload = b"A" * 72                    # Buffer overflow
payload += p64(0x00007ffff7a52390)     # system() - ไม่ต้องเดา!
payload += p64(0x0000000000400500)     # "/bin/sh" - ไม่ต้องเดา!
```

### วิธีสร้างสถานการณ์นี้
```bash
# Compile without PIE
gcc -no-pie -fno-PIE program.c -o program

# Disable ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# หรือ run แบบนี้
setarch $(uname -m) -R ./program
```

### ระดับความปลอดภัย: 0/10
- Attacker รู้ทุก address
- ไม่มีการสุ่มใดๆ
- เหมาะสำหรับ debugging เท่านั้น

---

## Case 2: ไม่มี PIE, มี ASLR ⚠️✅

### Memory Layout
```
Executable:  0x0000000000400000  (fixed) ⬅️ ตรงนี้เดิม!
.text:       0x0000000000400400  (fixed)
.data:       0x0000000000601000  (fixed)
.bss:        0x0000000000602000  (fixed)

libc:        0x00007f1234567000  (random) ⬅️ เปลี่ยนทุกครั้ง
system():    0x00007f1234590390  (random)
printf():    0x00007f12345a2800  (random)

stack:       0x00007ffe9abcd000  (random) ⬅️ เปลี่ยนทุกครั้ง
heap:        0x0000000001a03000  (random) ⬅️ เปลี่ยนทุกครั้ง
```

### ลักษณะ
- ⚠️ **Executable ยังคาดเดาได้**
- ✅ **Libraries ถูกสุ่ม**
- ✅ **Stack/Heap ถูกสุ่ม**
- 🎯 **Attacker มี base address ตายตัว**

### ตัวอย่างการโจมตี (ยังเป็นไปได้)
```python
# ใช้ ROP gadgets จาก executable เอง
payload = b"A" * 72
payload += p64(0x0000000000400686)  # pop rdi; ret - ไม่ต้องเดา!
payload += p64(0x0000000000601050)  # address ของ "/bin/sh" - รู้อยู่!
payload += p64(0x0000000000400450)  # plt@system - รู้อยู่!

# หรือ leak libc address แล้วคำนวณ offset
```

### Bypass Technique
1. **ใช้ gadgets จาก executable**
   - Executable address รู้อยู่แล้ว
   - หา ROP gadgets ใน .text section
   
2. **Leak libc address**
   ```c
   printf("Leaked: %p\n", printf);  // Leak function address
   // คำนวณ libc base = leaked_address - offset
   ```

3. **Partial RELRO bypass**
   - GOT entries ยังคง overwritable
   - GOT address คาดเดาได้

### วิธีสร้างสถานการณ์นี้
```bash
# Compile without PIE
gcc -no-pie -fno-PIE program.c -o program

# ASLR เปิดอยู่ (default)
cat /proc/sys/kernel/randomize_va_space  # แสดง 2
```

### ระดับความปลอดภัย: 4/10
- ป้องกัน simple attacks
- แต่ executable เป็นจุดอ่อน
- สถานการณ์นี้พบบ่อยใน legacy software

---

## Case 3: มี PIE, ไม่มี ASLR ⚠️⚠️

### Memory Layout
```
Executable:  0x0000555555554000  (fixed)* ⬅️ PIE แต่ไม่มีผล
.text:       0x0000555555554400  (fixed)*
.data:       0x0000555555756000  (fixed)*
.bss:        0x0000555555757000  (fixed)*

libc:        0x00007ffff7a0d000  (fixed)  ⬅️ ไม่ถูกสุ่ม
system():    0x00007ffff7a52390  (fixed)
printf():    0x00007ffff7a62800  (fixed)

stack:       0x00007ffffffde000  (fixed)  ⬅️ ไม่ถูกสุ่ม
heap:        0x0000555555758000  (fixed)*
```

**\*หมายเหตุ:** ถึง compile ด้วย PIE แต่ถ้า ASLR ปิด address ก็ยังเป็นค่าเดิม

### ลักษณะ
- 🎯 **PIE ไม่มีผลถ้า ASLR ปิด**
- 🎯 **ทุก address ยังคาดเดาได้**
- 🎯 **Base address แตกต่างจาก non-PIE**

### เปรียบเทียบ Address
```
Non-PIE executable: 0x0000000000400000
PIE executable:     0x0000555555554000

แต่ถ้า ASLR ปิด ก็ยังเป็นค่าเดิมทุกครั้ง!
```

### ตัวอย่างการโจมตี
```python
# ROP chain ด้วย PIE addresses (แต่ยังคาดเดาได้)
payload = b"A" * 72
payload += p64(0x00007ffff7a52390)     # system() - fixed!
payload += p64(0x0000555555554500)     # gadget - fixed!
```

### วิธีสร้างสถานการณ์นี้
```bash
# Compile with PIE
gcc -fPIE -pie program.c -o program

# Disable ASLR
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# Run
./program
```

### ระดับความปลอดภัย: 1/10
- PIE ไร้ประโยชน์โดยสมบูรณ์
- Address patterns แตกต่างจาก non-PIE เท่านั้น
- **สถานการณ์นี้ไม่ควรเกิดขึ้นจริง**

---

## Case 4: มี PIE, มี ASLR ✅✅

### Memory Layout
```
Executable:  0x000055abc1234000  (random) ⬅️ สุ่มทุกครั้ง!
.text:       0x000055abc1234400  (random)
.data:       0x000055abc1436000  (random)
.bss:        0x000055abc1437000  (random)

libc:        0x00007f9876543000  (random) ⬅️ สุ่มทุกครั้ง!
system():    0x00007f987656c390  (random)
printf():    0x00007f987657c800  (random)

stack:       0x00007ffd5432abcd  (random) ⬅️ สุ่มทุกครั้ง!
heap:        0x000055abc2a03000  (random) ⬅️ สุ่มทุกครั้ง!
```

### ลักษณะ
- ✅ **ทุก address ถูกสุ่ม**
- ✅ **Protection สูงสุด**
- ✅ **Exploitation ยากมาก**
- 🎯 **ต้อง leak address ก่อน**

### ตัวอย่าง Address ในแต่ละครั้ง
```bash
# Run ครั้งที่ 1
Executable: 0x000055e8f2c3d000
libc:       0x00007f3c89a0d000
stack:      0x00007ffc9234abcd

# Run ครั้งที่ 2  
Executable: 0x00005612ab456000
libc:       0x00007fe123789000
stack:      0x00007ffda9876543

# Run ครั้งที่ 3
Executable: 0x0000557823abc000
libc:       0x00007f9bc4567000
stack:      0x00007ffd12345678
```

### การโจมตีต้อง Leak Address ก่อน
```python
# Step 1: Leak PIE base
payload1 = b"%7$p"  # Leak stack -> calculate PIE base
leaked = execute(payload1)
pie_base = leaked - known_offset

# Step 2: Leak libc base
payload2 = construct_leak(pie_base)
libc_leaked = execute(payload2)
libc_base = libc_leaked - libc_offset

# Step 3: Build ROP chain with leaked addresses
payload3 = b"A" * 72
payload3 += p64(libc_base + system_offset)
payload3 += p64(libc_base + binsh_offset)
```

### Bypass Techniques (ยากมาก)

#### 1. Information Leak (วิธีหลัก)
```c
// Format string vulnerability
printf(user_input);  // Leak stack/addresses

// Buffer over-read
char buf[10];
read(0, buf, 20);  // Leak adjacent memory

// Use-after-free
// Leak heap addresses
```

#### 2. Partial Overwrite
```python
# เขียนทับแค่ 2 bytes ล่าง (12 bits entropy)
# Probability: 1/4096
payload = b"A" * 72 + b"\x00\x12"  # Overwrite 2 bytes only
```

#### 3. Brute Force (บน 32-bit only)
```python
# 32-bit PIE: ~16 bits entropy
# Can brute force: 2^16 = 65,536 attempts
# Success in ~30 seconds with remote target
```

### วิธีสร้างสถานการณ์นี้
```bash
# Compile with PIE (default ในหลาย distros)
gcc -fPIE -pie program.c -o program

# ASLR เปิดอยู่ (default)
cat /proc/sys/kernel/randomize_va_space  # แสดง 2

# Run
./program
```

### ระดับความปลอดภัย: 9/10
- Maximum protection
- Requires sophisticated attacks
- Industry standard

---

## สรุปเปรียบเทียบทั้ง 4 Cases

| Case | PIE | ASLR | Executable | Libraries | Stack/Heap | ระดับปลอดภัย | โจมตียาก | พบในระบบจริง |
|------|-----|------|------------|-----------|------------|-------------|----------|--------------|
| **1** | ❌ | ❌ | Fixed | Fixed | Fixed | 0/10 | 😈 ง่ายมาก | Debug only |
| **2** | ❌ | ✅ | Fixed | Random | Random | 4/10 | 😐 ปานกลาง | Legacy apps |
| **3** | ✅ | ❌ | Fixed | Fixed | Fixed | 1/10 | 😈 ง่ายมาก | ไม่ควรมี |
| **4** | ✅ | ✅ | Random | Random | Random | 9/10 | 😱 ยากมาก | Modern standard |

---

## Visual Comparison

### Case 1 (ไม่มี PIE, ไม่มี ASLR)
```
┌─────────────────────────┐
│ 0x00400000 [executable] │ ◄── คาดเดาได้
│ 0x00601000 [data/bss]   │ ◄── คาดเดาได้
├─────────────────────────┤
│ 0x7ffff7a0d000 [libc]   │ ◄── คาดเดาได้
│ 0x7ffffffde000 [stack]  │ ◄── คาดเดาได้
└─────────────────────────┘
🎯 Attacker: "รู้ทุกที่!"
```

### Case 2 (ไม่มี PIE, มี ASLR)
```
┌─────────────────────────┐
│ 0x00400000 [executable] │ ◄── คาดเดาได้
│ 0x00601000 [data/bss]   │ ◄── คาดเดาได้
├─────────────────────────┤
│ 0x7f1234567 [libc]      │ ◄── สุ่ม ❌
│ 0x7ffe9abcd [stack]     │ ◄── สุ่ม ❌
└─────────────────────────┘
⚠️ Attacker: "มี foothold ที่ executable"
```

### Case 3 (มี PIE, ไม่มี ASLR)
```
┌─────────────────────────┐
│ 0x555555554 [executable]│ ◄── คาดเดาได้ (PIE ไม่ทำงาน)
│ 0x555555756 [data/bss]  │ ◄── คาดเดาได้
├─────────────────────────┤
│ 0x7ffff7a0d [libc]      │ ◄── คาดเดาได้
│ 0x7ffffffde [stack]     │ ◄── คาดเดาได้
└─────────────────────────┘
🤷 PIE: "ฉันว่างงาน..."
```

### Case 4 (มี PIE, มี ASLR)
```
┌─────────────────────────┐
│ 0x55abc1234 [executable]│ ◄── สุ่ม ❌
│ 0x55abc1436 [data/bss]  │ ◄── สุ่ม ❌
├─────────────────────────┤
│ 0x7f9876543 [libc]      │ ◄── สุ่ม ❌
│ 0x7ffd5432a [stack]     │ ◄── สุ่ม ❌
└─────────────────────────┘
🛡️ Attacker: "ต้อง leak ก่อน..."
```

---

## Exploitation Difficulty Timeline

```
Case 1 → Case 2 → Case 4
  ↓        ↓        ↓
10 min   2 hours  2-3 days (with leak)
                  ∞ (without leak)

Case 3: Same as Case 1 (10 min)
```

---

## Recommendations

### ✅ Always Use (Production)
- **Case 4**: PIE + ASLR
- Modern standard
- Maximum security

### ⚠️ Limited Use  
- **Case 2**: No PIE + ASLR
- Legacy compatibility only
- Better than nothing

### ❌ Never Use
- **Case 1**: No PIE + No ASLR
- Debug/testing only
- Extremely vulnerable

- **Case 3**: PIE + No ASLR
- Makes no sense
- Waste of PIE overhead

---

## Quick Check Commands

```bash
# ตรวจสอบทุกอย่างของโปรแกรม
checksec --file=./program

# ตรวจสอบ ASLR
cat /proc/sys/kernel/randomize_va_space

# ทดสอบว่า address เปลี่ยนไหม
for i in {1..3}; do ldd ./program | grep libc; done

# ดู memory layout
cat /proc/self/maps | grep -E "stack|heap|libc"
```

นี่คือทั้งหมดทุกกรณีที่เป็นไปได้! Case 4 คือ best practice สำหรับระบบจริง 🛡️