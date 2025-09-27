## ตัวอย่างการทำงาน Stack ในการเรียก Function แบบละเอียดครบถ้วน

### โปรแกรม C:
```c
int add(int a, int b) {
    int result = a + b;
    return result;
}

int main() {
    int x = add(5, 3);
    return 0;
}
```

## Assembly Code ที่สมบูรณ์:

```assembly
add:
    push ebp
    mov ebp, esp
    sub esp, 4
    mov eax, [ebp+8]
    add eax, [ebp+12]
    mov [ebp-4], eax
    mov eax, [ebp-4]
    mov esp, ebp
    pop ebp
    ret

main:
    push ebp
    mov ebp, esp
    sub esp, 4
    push 3
    push 5
    call add
    add esp, 8
    mov [ebp-4], eax
    mov eax, 0
    mov esp, ebp
    pop ebp
    ret
```

## การทำงานขั้นตอนละเอียด:

### เริ่มต้น Stack (สมมติ):
```
Address  Value         Description
0x1000   (other data)  ← ESP = 0x1000
```

---

## ขั้นตอนที่ 1: เข้าสู่ main()

### 1.1: `push ebp` (ใน main)
- เก็บ old EBP ของระบบ (สมมติ 0x2000)
- ESP ลดลง 4 bytes

```
Address  Value         Description
0x0FFC   0x2000        ← old EBP (ของระบบ)
0x1000   (other data)  ← ESP = 0x0FFC
```
**Register state:** EBP = 0x2000, ESP = 0x0FFC

### 1.2: `mov ebp, esp` (ใน main)
- คัดลอกค่า ESP ไปยัง EBP

```
Address  Value         Description
0x0FFC   0x2000        ← old EBP (ของระบบ)
0x1000   (other data)
```
**Register state:** EBP = 0x0FFC, ESP = 0x0FFC

### 1.3: `sub esp, 4` (ใน main)
- จองพื้นที่สำหรับ local variable `x`

```
Address  Value         Description
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP, EBP ชี้ตรงนี้
0x1000   (other data)  ← ESP = 0x0FF8
```
**Register state:** EBP = 0x0FFC, ESP = 0x0FF8

---

## ขั้นตอนที่ 2: เตรียม Parameters

### 2.1: `push 3` (parameter b)
- Push parameter ที่ 2

```
Address  Value         Description
0x0FF4   3             ← parameter b
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP, EBP ชี้ตรงนี้
0x1000   (other data)  ← ESP = 0x0FF4
```
**Register state:** EBP = 0x0FFC, ESP = 0x0FF4

### 2.2: `push 5` (parameter a)
- Push parameter ที่ 1

```
Address  Value         Description
0x0FF0   5             ← parameter a
0x0FF4   3             ← parameter b
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP, EBP ชี้ตรงนี้
0x1000   (other data)  ← ESP = 0x0FF0
```
**Register state:** EBP = 0x0FFC, ESP = 0x0FF0

---

## ขั้นตอนที่ 3: เรียก Function

### 3.1: `call add`
- CPU ทำ 2 อย่าง:
  1. Push return address (สมมติ 0x401020)
  2. Jump ไปยัง add function

```
Address  Value         Description
0x0FEC   0x401020      ← return address
0x0FF0   5             ← parameter a
0x0FF4   3             ← parameter b
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP ของระบบ, EBP ยังชี้ตรงนี้
0x1000   (other data)  ← ESP = 0x0FEC
```
**Register state:** EBP = 0x0FFC, ESP = 0x0FEC

---

## ขั้นตอนที่ 4: เข้าสู่ add() Function

### 4.1: `push ebp` (ใน add)
- เก็บ old EBP ของ main (0x0FFC)

```
Address  Value         Description
0x0FE8   0x0FFC        ← old EBP ของ main
0x0FEC   0x401020      ← return address
0x0FF0   5             ← parameter a
0x0FF4   3             ← parameter b
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP ของระบบ
0x1000   (other data)  ← ESP = 0x0FE8
```
**Register state:** EBP = 0x0FFC, ESP = 0x0FE8

### 4.2: `mov ebp, esp` (ใน add)
- ตั้ง EBP ใหม่เป็นจุดอ้างอิง

```
Address  Value         Description
0x0FE8   0x0FFC        ← old EBP ของ main, EBP ชี้ตรงนี้
0x0FEC   0x401020      ← return address (EBP + 4)
0x0FF0   5             ← parameter a (EBP + 8)
0x0FF4   3             ← parameter b (EBP + 12)
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP ของระบบ
0x1000   (other data)  ← ESP = 0x0FE8
```
**Register state:** EBP = 0x0FE8, ESP = 0x0FE8

### 4.3: `sub esp, 4` (ใน add)
- จองพื้นที่สำหรับ local variable `result`

```
Address  Value         Description
0x0FE4   (undefined)   ← พื้นที่สำหรับ result (EBP - 4)
0x0FE8   0x0FFC        ← old EBP ของ main, EBP ชี้ตรงนี้
0x0FEC   0x401020      ← return address (EBP + 4)
0x0FF0   5             ← parameter a (EBP + 8)
0x0FF4   3             ← parameter b (EBP + 12)
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP ของระบบ
0x1000   (other data)  ← ESP = 0x0FE4
```
**Register state:** EBP = 0x0FE8, ESP = 0x0FE4

---

## ขั้นตอนที่ 5: การทำงานใน add()

### 5.1: `mov eax, [ebp+8]`
- โหลด parameter a (5) เข้า EAX

```
Memory ยังเหมือนเดิม
```
**Register state:** EBP = 0x0FE8, ESP = 0x0FE4, **EAX = 5**

### 5.2: `add eax, [ebp+12]`
- บวก parameter b (3) เข้ากับ EAX

```
Memory ยังเหมือนเดิม
```
**Register state:** EBP = 0x0FE8, ESP = 0x0FE4, **EAX = 8** (5+3)

### 5.3: `mov [ebp-4], eax`
- เก็บผลลัพธ์ (8) ใน local variable result

```
Address  Value         Description
0x0FE4   8             ← result = 8 (EBP - 4)
0x0FE8   0x0FFC        ← old EBP ของ main, EBP ชี้ตรงนี้
0x0FEC   0x401020      ← return address (EBP + 4)
0x0FF0   5             ← parameter a (EBP + 8)
0x0FF4   3             ← parameter b (EBP + 12)
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP ของระบบ
0x1000   (other data)  ← ESP = 0x0FE4
```
**Register state:** EBP = 0x0FE8, ESP = 0x0FE4, EAX = 8

### 5.4: `mov eax, [ebp-4]`
- โหลด return value เข้า EAX (กฎการ return ใน x86)

```
Memory ยังเหมือนเดิม
```
**Register state:** EBP = 0x0FE8, ESP = 0x0FE4, **EAX = 8**

---

## ขั้นตอนที่ 6: Function Epilogue ของ add()

### 6.1: `mov esp, ebp`
- คืนค่า stack pointer กลับไปที่ base pointer

```
Address  Value         Description
0x0FE4   8             ← result = 8
0x0FE8   0x0FFC        ← old EBP ของ main, EBP และ ESP ชี้ตรงนี้
0x0FEC   0x401020      ← return address
0x0FF0   5             ← parameter a
0x0FF4   3             ← parameter b
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP ของระบบ
0x1000   (other data)
```
**Register state:** EBP = 0x0FE8, **ESP = 0x0FE8**, EAX = 8

### 6.2: `pop ebp`
- คืนค่า old EBP ของ main กลับมา

```
Address  Value         Description
0x0FE4   8             ← result = 8
0x0FE8   0x0FFC        ← (ค่าที่ถูก pop แล้ว)
0x0FEC   0x401020      ← return address
0x0FF0   5             ← parameter a
0x0FF4   3             ← parameter b
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP ของระบบ
0x1000   (other data)  ← ESP = 0x0FEC
```
**Register state:** **EBP = 0x0FFC** (คืนมาแล้ว), ESP = 0x0FEC, EAX = 8

### 6.3: `ret`
- Pop return address และ jump กลับไป main

```
Address  Value         Description
0x0FE4   8             ← result = 8
0x0FE8   0x0FFC        
0x0FEC   0x401020      ← (ค่าที่ถูก pop แล้ว)
0x0FF0   5             ← parameter a
0x0FF4   3             ← parameter b
0x0FF8   (undefined)   ← พื้นที่สำหรับ x
0x0FFC   0x2000        ← old EBP ของระบบ, EBP ชี้ตรงนี้
0x1000   (other data)  ← ESP = 0x0FF0
```
**Register state:** EBP = 0x0FFC, **ESP = 0x0FF0**, EAX = 8
**CPU กลับมาทำงานที่ main ต่อจาก instruction หลัง call**

---

## ขั้นตอนที่ 7: กลับมาที่ main()

### 7.1: `add esp, 8`
- ลบ parameters ออกจาก stack (2 parameters × 4 bytes = 8 bytes)

```
Address  Value         Description
0x0FE4   8             ← result = 8
0x0FE8   0x0FFC        
0x0FEC   0x401020      
0x0FF0   5             ← parameter a
0x0FF4   3             ← parameter b
0x0FF8   (undefined)   ← พื้นที่สำหรับ x, ESP ชี้ตรงนี้
0x0FFC   0x2000        ← old EBP ของระบบ, EBP ชี้ตรงนี้
0x1000   (other data)
```
**Register state:** EBP = 0x0FFC, **ESP = 0x0FF8**, EAX = 8

### 7.2: `mov [ebp-4], eax`
- เก็บ return value (8) ใน local variable x

```
Address  Value         Description
0x0FE4   8             ← result = 8
0x0FE8   0x0FFC        
0x0FEC   0x401020      
0x0FF0   5             ← parameter a
0x0FF4   3             ← parameter b
0x0FF8   8             ← x = 8 (EBP - 4)
0x0FFC   0x2000        ← old EBP ของระบบ, EBP ชี้ตรงนี้
0x1000   (other data)  ← ESP = 0x0FF8
```
**Register state:** EBP = 0x0FFC, ESP = 0x0FF8, EAX = 8

### 7.3: `mov eax, 0` (return 0)
- เตรียม return value สำหรับ main

```
Memory ยังเหมือนเดิม
```
**Register state:** EBP = 0x0FFC, ESP = 0x0FF8, **EAX = 0**

---

## ขั้นตอนที่ 8: Function Epilogue ของ main()

### 8.1: `mov esp, ebp`
- คืนค่า stack pointer

```
Address  Value         Description
0x0FE4   8             
0x0FE8   0x0FFC        
0x0FEC   0x401020      
0x0FF0   5             
0x0FF4   3             
0x0FF8   8             ← x = 8
0x0FFC   0x2000        ← old EBP ของระบบ, EBP และ ESP ชี้ตรงนี้
0x1000   (other data)
```
**Register state:** EBP = 0x0FFC, **ESP = 0x0FFC**, EAX = 0

### 8.2: `pop ebp`
- คืนค่า old EBP ของระบบ

```
Address  Value         Description
0x0FE4   8             
0x0FE8   0x0FFC        
0x0FEC   0x401020      
0x0FF0   5             
0x0FF4   3             
0x0FF8   8             ← x = 8
0x0FFC   0x2000        ← (ค่าที่ถูก pop แล้ว)
0x1000   (other data)  ← ESP = 0x1000
```
**Register state:** **EBP = 0x2000** (คืนสู่ระบบ), ESP = 0x1000, EAX = 0

### 8.3: `ret`
- กลับสู่ระบบปฏิบัติการ

```
Stack กลับสู่สภาพเดิม
Address  Value         Description
0x1000   (other data)  ← ESP = 0x1000
```
**Register state:** EBP = 0x2000, ESP = 0x1000, EAX = 0

---

























### ก่อน `mov esp, ebp`:
```
Address  Value         Description
0x0FE4   8             ← result = 8
0x0FE8   0x0FFC        ← old EBP ของ main, EBP ชี้ตรงนี้
0x0FEC   0x401020      ← return address
0x0FF0   5             ← parameter a, ESP ชี้ตรงนี้ (บนสุดตอนนี้)
```
**Register:** EBP = 0x0FE8, ESP = 0x0FF0

### หลัง `mov esp, ebp`:
```
Address  Value         Description
0x0FE4   8             ← result = 8
0x0FE8   0x0FFC        ← old EBP ของ main, EBP และ ESP ชี้ตรงนี้
0x0FEC   0x401020      ← return address
0x0FF0   5             ← parameter a
```
**Register:** EBP = 0x0FE8, **ESP = 0x0FE8**

### เมื่อ `pop ebp`:
- ESP ชี้ไปที่ address 0x0FE8
- **ตำแหน่งที่ ESP ชี้ (0x0FE8) คือ "บนสุดของ stack ใหม่"**
- POP จะ:
  1. อ่านค่าจาก [ESP] = [0x0FE8] = 0x0FFC
  2. เก็บค่า 0x0FFC ลงใน EBP
  3. เพิ่ม ESP ขึ้น 4 bytes → ESP = 0x0FEC

### หลัง `pop ebp`:
```
Address  Value         Description
0x0FE4   8             ← result = 8
0x0FE8   0x0FFC        ← (ค่าที่ถูก pop ไปแล้ว)
0x0FEC   0x401020      ← return address, ESP ชี้ตรงนี้ (บนสุดใหม่)
0x0FF0   5             ← parameter a
```
**Register:** **EBP = 0x0FFC** (คืนค่ามาแล้ว), ESP = 0x0FEC








## การทำงานของ RET:

### RET เทียบเท่ากับ:
```assembly
pop eip     ; ดึง return address จาก stack ใส่ใน instruction pointer
; หรือในระบบ 64-bit: pop rip
```

### ขั้นตอนการทำงาน:
1. **อ่านค่าจากตำแหน่งที่ ESP ชี้** → ได้ return address
2. **โหลด return address ลงใน EIP** (instruction pointer)
3. **เพิ่ม ESP ขึ้น 4 bytes** (หรือ 8 bytes ใน 64-bit)
4. **CPU เริ่มทำงานจาก address ใหม่**

## ตัวอย่างการทำงาง RET:

### ก่อน RET:
```
Address  Value         Description
0x0FE8   0x0FFC        ← old EBP (ถูก pop ไปแล้ว)
0x0FEC   0x401020      ← return address, ESP ชี้ตรงนี้
0x0FF0   5             ← parameter a  
0x0FF4   3             ← parameter b
```
**Register:** EBP = 0x0FFC, ESP = 0x0FEC, **EIP = 0x400500** (สมมติ)

### เมื่อ RET ทำงาน:
1. **อ่าน [ESP]**: ได้ค่า 0x401020
2. **โหลดลง EIP**: EIP = 0x401020
3. **เพิ่ม ESP**: ESP = ESP + 4 = 0x0FF0

### หลัง RET:
```
Address  Value         Description
0x0FE8   0x0FFC        ← old EBP
0x0FEC   0x401020      ← (ค่าที่ถูก pop ไปแล้ว)
0x0FF0   5             ← parameter a, ESP ชี้ตรงนี้
0x0FF4   3             ← parameter b
```
**Register:** EBP = 0x0FFC, ESP = 0x0FF0, **EIP = 0x401020**

**CPU จะกระโดดไปทำงานที่ address 0x401020 (กลับไปที่ main)**



