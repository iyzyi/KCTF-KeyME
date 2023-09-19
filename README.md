# 提交信息

团队名称：`BXS-iyzyi`

团长QQ：`295982055`

参赛题目：`KCTF-KeyME.exe`

题目答案(攻击脚本)：详见`KeyGenByHacker.zip`

详细的题目设计说明和破解思路：详见`设计说明和破解思路.md`

其他需要说明的各个问题：

* 选择的是CrackMe中的一人一密模式 （方案二） 

* KCTF-KeyME.exe的sha256为141e8f96636898efa6e75b3198ae9c24cb3189dd29ab9512d9c35e9f522ffc20，故按照出题要求给出一组注册码：

  ```
  user: 141E8F96636898EF
  serial: dd8c5dd5bff047cb86c51fc808254c0950ebd2d9c7e6b34679a6cda7f96ea0f46d105248c68b6534546d34c26534546d34c26534542538d289a28b2d14d06534546614d225146289a28b6614d249a7096d10522538d22538d289a28b48a21b2d14d041a69b2d14d06614d289a28b25146250a28948a21b48c68b48c68b49829948a21b6d105249a7092c345289a28b6534542c34522d14d050a2896d105225146289a28b6d105249a7092d14d049a7096d34c26d10522d14d049a70948a21b2d14d048c68b48a21b49a70925146248c68b41a69b08a69948c68b48c68b498299
  ```

* 本题要求攻击方找出KCTF的注册码，如下：

  ```
  user: KCTF
  serial: 83bde72e2806ce3c8f424e242559a66314bb37008d62a69bfd1a960f8e4102c850a28948c68b49a70989a28b89a28b6614d24982996614d249a7096d34c26d10522c345241a69b6d105208a69949a70950a28949829941a69b48a21b50a28925146289a28b48c68b50a2896614d241a69b89a28b49829948c68b49829989a28b89a28b41a69b48a21b25146248c68b48c68b25146249a7092538d241a69b2c34522538d241a69b65345489a28b48a21b6534542538d248c68b6614d26d105250a2896d105249a70948c68b6d105208a69941a69b89a28b50a28941a69b2d14d0
  ```

* 运行环境：仅支持win10/64。有反调试，但是保证在纯净win10/64虚拟机内可以正常运行。

* 未使用第三方保护工具，但有手工处理设计了一个简单的vm，详情请看设计文档。

# 设计说明和破解思路

看雪的神仙师傅太多了，菜鸡自认为做不出题来，所以只能转向防守方出个题了。

具体的联系方式、备注等信息在`提交信息.md`里，这里只说下设计说明和攻击思路。

## 设计说明

user长度1~254，注册码长度448，注册码字符集为0-9a-f

将user取md5后，前8字节、后8字节分别再次md5，分别作为第一、二部分的输出验证

将serial从hex字符串转换成byte数组，长度224，前32字节作为第一部分的输入，后192字节作为第二部分的输入。

然后分两部分进行验证。

### 第一部分

#### qixi-vm

一个小的vm。

涉及的小算法我之前在看雪发过：https://bbs.pediy.com/thread-261646.htm。在上文的基础上多加了一个&运算。这个小算法没多大难度，但是编译出来的汇编指令是很臃肿的，嵌套了15层的话，汇编指令大概有几十万行。

编译后只涉及了六种汇编指令，mov, shr, shl, and, xor, add，所以我把这六种指令设计成了一个小vm，甚至可能都不足以被称之为vm。

指令格式如下：

```c++
uint16_t xor_data[] = {0x0123, 0x4567, 0x89ab, 0xcdef, 0x0f1e, 0x2d3c, 0x4b5a, 0x6978};
int pointer = 0;
uint32_t reg[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

struct VmCmd{
	uint32_t and_param;
	uint8_t rubbish_size;	//垃圾指令大小 
	uint8_t xor_index; 
	uint8_t reg_byte;
	uint8_t dst;			//目的操作数 
	uint8_t src;			//源操作数 
	uint8_t op_byte;		//六种指令 
	uint8_t other_op_param; 
};

uint32_t encrypt_vm(uint32_t plain){
	
	reg[15] = plain; 		// [ebp+plain]
	
	while(pointer < (sizeof(vm_data) / sizeof(vm_data[0]))) {
		VmCmd vcmd;
		vcmd.and_param = *(uint32_t*)(vm_data + pointer);
		vcmd.rubbish_size = (((vcmd.and_param >> 16) & 1) << 1) + ((vcmd.and_param >> 7) & 1);
		vcmd.xor_index = (((vcmd.and_param >> 27) & 1) << 2) + (((vcmd.and_param >> 19) & 1) << 1) + ((vcmd.and_param >> 8) & 1);
		vcmd.reg_byte = *(vm_data + pointer + 4) ^ ((xor_data[vcmd.xor_index] >> 8) & 0xff);
		vcmd.dst = (vcmd.reg_byte >> 4) & 0xf;
		vcmd.src = (vcmd.reg_byte) & 0xf;
		vcmd.op_byte = *(vm_data + pointer + 4 + 1 + vcmd.rubbish_size) ^ (xor_data[vcmd.xor_index] & 0xff);
		vcmd.other_op_param = *(vm_data + pointer + 4 + 1 + vcmd.rubbish_size + 1);
		uint16_t new_data = ((*(vm_data + pointer + 4)) << 8) + (*(vm_data + pointer + 4 + 1 + vcmd.rubbish_size));
		for (int i = 0; i < 7; i++){
			xor_data[i] = xor_data[i+1];
		}
		xor_data[7] = new_data;
		pointer += 4 + 1 + vcmd.rubbish_size + 1 + 1;

		if (vcmd.op_byte & 64){				//and
			reg[vcmd.dst] &= vcmd.and_param;
		} else if (vcmd.op_byte & 32){		//shr
			reg[vcmd.dst] >>= vcmd.other_op_param;
		} else if (vcmd.op_byte & 16){		//shl
			reg[vcmd.dst] <<= vcmd.other_op_param;
		} else if (vcmd.op_byte & 8){		//xor
			reg[vcmd.dst] ^= reg[vcmd.src];
		} else if (vcmd.op_byte & 4){		//mov
			reg[vcmd.dst] = reg[vcmd.src];
		} else if (vcmd.op_byte & 2){		//add
			reg[vcmd.dst] += reg[vcmd.src];
		}
	}
	
	return reg[14];		//eax
}
```

这个vm是我手工处理的，按照防守方的出题要求，在这里说下怎么处理的吧。虽然我感觉师傅们对此应该不感兴趣。

编译原算法后，使用ida打开，定位至加密函数。用下面的脚本导出汇编代码

```
print "[-] 开始！"
import idautils
ea = idc.ScreenEA()
addrs = idautils.FuncItems(ea)
op_list = []
for addr in addrs:
    op_list.append((GetMnem(addr), GetOpnd(addr, 0),GetOpnd(addr, 1)))
with open('d:\\opcode.txt', 'w')as f:
    f.write(str(op_list))
print "[+] 结束！"
```

然后用下面脚本处理得到vm的字节码：

```python
import random, ctypes

def dont_remove(i):
    import re
    if i[0] == 'add' and i[1] == 'esp':
        return False
    if i[0] == 'mov' and i[1] == 'ebp':
        return False
    r = re.match(r'(add)|(shr)|(shl)|(mov)|(and)|(xor)', i[0])
    if r != None:
        return True
    return False

def is_num(s):
    import re
    if s == '':
        return False
    r = re.match(r'([0-9a-fA-F]+?h)|([0-9]+?)', s)
    if r != None:
        return True
    return False


def list2dict(l):
    dic = {}
    for item in set(l):
        dic[item] = l.count(item)
    dic = sorted(dic.items(), key=lambda item:item[1])
    print('列表共计%d个元素，统计结果：' % len(dic))
    for item in dic:
        print("%15s\t\t%d" % (item[0], item[1]))
    return dic


def int2list(num):
    #print(hex(num))
    l = [0] * 4
    l[0] = [num & 0xff]
    l[1] = [(num >> 8) & 0xff]
    l[2] = [(num >> 16) & 0xff]
    l[3] = [(num >> 24) & 0xff]
    return l[0] + l[1] + l[2] + l[3]


def data2list(and_param, reg_byte, rubbish_size, op_byte, other_op_param):
    # list有7+offset个元素，是一条vm指令
    # 4 + 1 + offset + 1 + 1
    rubbish = random.randint(0, 2 ** (rubbish_size * 8))
    #print(and_param, reg_byte, rubbish, op_byte, other_op_param)
    return int2list(and_param) + [reg_byte] + int2list(rubbish)[:rubbish_size] + [op_byte] + [other_op_param]


def hex2uint(s):
    if s[-1] == 'h':
        return int(s[:-1], 16)
    else:
        return int(s, 16)



with open(r'opcode.txt')as f:
    b = f.read()
l = eval(b)


ll = []
for i in l:
    if dont_remove(i):
        ll.append(i)
        #if i[2] == '[ebp+p]':
        #    print(i)
print(len(l), len(ll))


op_1 = [i[1] for i in ll]
op_dic = list2dict(op_1)

op_2 = [i[2] for i in ll]
op_dic = list2dict(op_2)


reg = []
for i in ll:
    if not is_num(i[2]):
        #print(i[2])
        reg.append(i[2])
reg_dict = list2dict(reg)
reg_dic = {}
for i in range(len(reg_dict)):
    reg_dic[reg_dict[i][0]] = i
print(reg_dic)
# {'[ebp+var_30]': 0, '[ebp+var_10]': 1, '[ebp+var_2C]': 2, '[ebp+var_14]': 3, '[ebp+var_28]': 4, '[ebp+var_18]': 5, '[ebp+var_24]': 6, '[ebp+var_20]': 7, '[ebp+var_1C]': 8, 'edi': 9, 'esi': 10, 'ebx': 11, 'ecx': 12, 'edx': 13, 'eax': 14, '[ebp+p]': 15}


vm_data = []
one = []
xor_data = [0x0123, 0x4567, 0x89ab, 0xcdef, 0x0f1e, 0x2d3c, 0x4b5a, 0x6978]         # 16 bit, 异或的初始值
c = 0
for opcode in ll:
    '''
    if c == 100:
        break
    c += 1
    '''
    #print(xor_data)
    op, n1, n2 = opcode[0], opcode[1], opcode[2]
    n2_is_reg = not is_num(opcode[2])
    if not n2_is_reg:
        n2 = hex2uint(n2)
    # (add)|(shr)|(shl)|(mov)|(and)|(xor)

    if op == 'and':
        # idapython可验证均为and reg, num.
        and_param = n2

        reg_byte = (reg_dic[n1] << 4) + random.randint(0, 0xf)

        op_byte = 0b11000000 + random.randint(0, 1)

        other_op_param = random.randint(0, 0xff)

        rubbish_size = (((and_param >> 16) & 0b1) << 1) + ((and_param >> 7) & 0b1)
        #print(bin(and_param), rubbish_size)

        xor_index = (((and_param >> 27) & 0b1) << 2) + (((and_param >> 19) & 0b1) << 1) + ((and_param >> 8) & 0b1)
        reg_byte ^= ((xor_data[xor_index] >> 8) & 0xff)
        op_byte ^= (xor_data[xor_index] & 0xff)
        new_data = (reg_byte << 8) + op_byte
        for i in range(7):
            xor_data[i] = xor_data[i+1]
        xor_data[7] = new_data

        one = data2list(and_param, reg_byte, rubbish_size, op_byte, other_op_param)
        #print(one)

    elif op == 'shr':
        # idapython可验证均为and reg, num.
        and_param = random.randint(0, 0xffffffff)

        reg_byte = (reg_dic[n1] << 4) + random.randint(0, 0xf)

        op_byte = 0b10100000 + random.randint(0, 1)

        other_op_param = n2

        rubbish_size = (((and_param >> 16) & 0b1) << 1) + ((and_param >> 7) & 0b1)
        
        xor_index = (((and_param >> 27) & 0b1) << 2) + (((and_param >> 19) & 0b1) << 1) + ((and_param >> 8) & 0b1)
        reg_byte ^= ((xor_data[xor_index] >> 8) & 0xff)
        op_byte ^= (xor_data[xor_index] & 0xff)
        new_data = (reg_byte << 8) + op_byte
        for i in range(7):
            xor_data[i] = xor_data[i+1]
        xor_data[7] = new_data

        one = data2list(and_param, reg_byte, rubbish_size, op_byte, other_op_param)
        #print(one)

    elif op == 'shl':
        # idapython可验证均为and reg, num.
        and_param = random.randint(0, 0xffffffff)

        reg_byte = (reg_dic[n1] << 4) + random.randint(0, 0xf)

        op_byte = 0b10010000 + random.randint(0, 1)

        other_op_param = n2

        rubbish_size = (((and_param >> 16) & 0b1) << 1) + ((and_param >> 7) & 0b1)
        
        xor_index = (((and_param >> 27) & 0b1) << 2) + (((and_param >> 19) & 0b1) << 1) + ((and_param >> 8) & 0b1)
        reg_byte ^= ((xor_data[xor_index] >> 8) & 0xff)
        op_byte ^= (xor_data[xor_index] & 0xff)
        new_data = (reg_byte << 8) + op_byte
        for i in range(7):
            xor_data[i] = xor_data[i+1]
        xor_data[7] = new_data

        one = data2list(and_param, reg_byte, rubbish_size, op_byte, other_op_param)
        #print(one)
    
    
    
    elif op == 'xor':
        # idapython可验证第一个操作数均为寄存器，第两个操作数均为寄存器或栈中某处。
        and_param = random.randint(0, 0xffffffff)

        reg_byte = (reg_dic[n1] << 4) + (reg_dic[n2])
        print('xor %s, %s'%(reg_dic[n1], reg_dic[n2]))
        op_byte = 0b00001000 + random.randint(0, 1)

        other_op_param = random.randint(0, 0xff)

        rubbish_size = (((and_param >> 16) & 0b1) << 1) + ((and_param >> 7) & 0b1)
        
        xor_index = (((and_param >> 27) & 0b1) << 2) + (((and_param >> 19) & 0b1) << 1) + ((and_param >> 8) & 0b1)
        reg_byte ^= ((xor_data[xor_index] >> 8) & 0xff)
        op_byte ^= (xor_data[xor_index] & 0xff)
        new_data = (reg_byte << 8) + op_byte
        for i in range(7):
            xor_data[i] = xor_data[i+1]
        xor_data[7] = new_data

        one = data2list(and_param, reg_byte, rubbish_size, op_byte, other_op_param)
        #print(one)
    
    elif op == 'mov':
        # idapython可验证两个操作数均为寄存器或栈中某处。
        and_param = random.randint(0, 0xffffffff)

        reg_byte = (reg_dic[n1] << 4) + (reg_dic[n2])

        op_byte = 0b00000100 + random.randint(0, 1)

        other_op_param = random.randint(0, 0xff)

        rubbish_size = (((and_param >> 16) & 0b1) << 1) + ((and_param >> 7) & 0b1)
        
        xor_index = (((and_param >> 27) & 0b1) << 2) + (((and_param >> 19) & 0b1) << 1) + ((and_param >> 8) & 0b1)
        reg_byte ^= ((xor_data[xor_index] >> 8) & 0xff)
        op_byte ^= (xor_data[xor_index] & 0xff)
        new_data = (reg_byte << 8) + op_byte
        for i in range(7):
            xor_data[i] = xor_data[i+1]
        xor_data[7] = new_data

        one = data2list(and_param, reg_byte, rubbish_size, op_byte, other_op_param)
        #print(one)
    
    elif op == 'add':
        # 其实都是add     eax, eax
        and_param = random.randint(0, 0xffffffff)

        reg_byte = (reg_dic[n1] << 4) + (reg_dic[n2])

        op_byte = 0b00000010 + random.randint(0, 1)

        other_op_param = random.randint(0, 0xff)

        rubbish_size = (((and_param >> 16) & 0b1) << 1) + ((and_param >> 7) & 0b1)
        
        xor_index = (((and_param >> 27) & 0b1) << 2) + (((and_param >> 19) & 0b1) << 1) + ((and_param >> 8) & 0b1)
        reg_byte ^= ((xor_data[xor_index] >> 8) & 0xff)
        op_byte ^= (xor_data[xor_index] & 0xff)
        new_data = (reg_byte << 8) + op_byte
        for i in range(7):
            xor_data[i] = xor_data[i+1]
        xor_data[7] = new_data

        one = data2list(and_param, reg_byte, rubbish_size, op_byte, other_op_param)
        #print(one)


    vm_data += one
    
    for i in xor_data:
        print(hex(i)[2:], end=' ')
    print()
    print(hex((reg_byte << 8) + op_byte), hex(new_data), op)
    

print(len(vm_data))
vm_data = '{%s}' % str(vm_data)[1:-1]
with open(r'vm_data.txt', 'w')as f:
    f.write(vm_data)
```

由于vm指令的设计问题，只适用于所涉及的变量不多于16个的汇编代码。因为源操作数和目标操作数分别只有4个bit来标识。

哦哦，对了，为了增加难度，我把vm的字节码改了4个字节。vm_data中的第1122145个数据应该是0xf496b3af，为了迷惑师傅们，我改成了111 112 113 114，然后使用TLS回调改回正确的字节码0xf496b3af。

这个数据是最后一个&的参数。感觉这会是一个坑点。

#### aes256_shellcode

上一步的输出转为这一步的输入。

这一步是调用了微软的crypto api，算法是aes256 cbc iv=0000000000000000，key是sha256(1_L0V3_BXS_F0REVER!)

看起来简单，但我是写了个shellcode的，调用比较隐蔽。

动态获取kernel32.dll的基址，通过比较hash获取LoadLibraryA的地址，导入advapi32.dll，然后继续通过比较hash获取CryptAcquireContextA，CryptCreateHash，CryptHashData，CryptDeriveKey，CryptEncrypt的地址，分别push参数后调用。

#### 32Byte转换成16Byte

```
for (int i = 0; i < 16; i++) {
	if ((uint8_t)(step1_2[i * 2] + 0x7f) != step1_2[i * 2 + 1]) {
		return false;
}
	step1_1[i] = step1_2[2 * i];
}
```

#### 魔改aes

然后再走一波aes 256 ecb，key是Wo YongYuan XiHuan KanXun LunTan。不过这次是魔改的aes。

原版aes的不可约多项式是283，我改成了299。

不过，网上的aes的代码，大多都是利用不可约多项式已经生成了s盒和逆s盒的， 所以魔改起来还是有些难度的。

具体的魔改原理，师傅们可以去网上看，我这里就不过多展开了。

对了，为了欺骗师傅们使用的识别加密算法的插件，我刻意保留了原版的s盒和逆s盒。不知道能不能骗到师傅们。

### 第二部分

#### 码分复用解码

上学期准备计网结课考试的时候，就觉得这个算法放到逆向里，绝对很有意思。所以就放到这里面了。

不知道网上有没有现成的代码，反正这里我是自己写的，和官方的标准肯定有差异，但是能保证有相应的逆算法就可以。

这个算法本质上来说，其实就是空间向量的合成与分解。具体的师傅们可以去网上搜，这里不过多展开了。

192Byte -> 32Byte

#### 模意义下的高斯消元

这个算法用于解多元单模线性方程组。我这里选用的模数是65423。

注册机是将16Byte的数据，分别乘以一个系数（由key数组生成）后求和取模，1B的数据生成一个2B的结果，共32Byte。

验证的时候就是用模意义下的高斯消元求出原来的那个1B的数据。

#### 利用md5进行check

这个思路来自《加密与解密》第四版的645页。师傅们可以去读下。具体的看攻击脚本吧。

最后输出16B，与user的md5的后8字节的md5进行验证

## 攻击思路

首先去下花指令。花指令的数量不少，手动去花不太现实。不过好在种类不多，一共也就十种左右吧。发现一次后就可以写个脚本批量去一下。

然后过反调试。反调试我接触不过，所以本题的反调试只是聊胜于无罢了。而且我故意让反调试清一色地调用exit()，所以只需要找到一处反调试，就可以查看交叉引用，直接找到所有的反调试。所以本题的反调试没多大意思。

最后一步就是逆向了。

大多数都是算法求逆，考验算法功底。这里只捡几个关键的点来说。

### vm

读开头的几百行汇编，应该能反应过来其实是一个嵌套的格式。

然后到最后的几百行提取所涉及的参数就行。

一个坑点在于最后一个&的参数被改过了，需要发现TLS回调的那个函数。

### aes256_shellcode

两种方法：

直接把汇编dump出来，改hash，使得CryptEncrypt函数改成CryptDecrypt，就能跑，注意CryptEncrypt比CryptDecrypt多个参数，需要调下栈平衡

或者有crypto api经验的可以直接知道是aes256 cbc。

### 魔改aes

关于不可约多项式生成s盒和逆s盒，可以参考

https://blog.csdn.net/u011516178/article/details/81221646

### 模意义下的高斯消元

正向的算法直接导出就能用，逆向的算法就是一个叠乘相加，难度不大。

### 利用md5进行check

需要先用已知的一组注册码求出攻击脚本中的H数组，这一过程需要导出整个第二部分的正向算法。

有了H数组后，就可以逆向写出求解注册码的逻辑。

