from _ast import AST, Constant
from ast import *
from ast import Bytes, FunctionDef, Num, Str
import astor
import random
import base64
import sys
import os

hash2str_name = None

def random_name() -> str:
    # return ''.join(chr(random.randint(0x61, 0x7a)) for _ in range(random.randint(3, 4)))
    length = 24
    num = random.randint(0, 2 ** length)
    binary_str = format(num, '0%db' % length)
    binary_str = 'o' + binary_str.replace('0', '0').replace('1', 'o')
    return binary_str

def str2hash(input):
    CUSTOM_ALPHABET = '-_+!1@2#3$4%5^6&7*8(9)0qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFG'.encode()
    STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'.encode()
    ENCODE_TRANS = bytes.maketrans(STANDARD_ALPHABET, CUSTOM_ALPHABET)
    return base64.b64encode(input.encode()).translate(ENCODE_TRANS).decode()

def toChr(x):
    result = BinOp(
        left=Call(
            func=Name(id='chr', ctx=Load()),
            args=[Constant(ord(x[0]))],
            keywords=[], starargs=None, kwargs=None
        ),
        op=Add(),
        right=Call(
            func=Name(id='chr', ctx=Load()),
            args=[Constant(ord(x[1]))],
            keywords=[], starargs=None, kwargs=None
        )
    )
    index = 2
    while index < len(x):
        result.right = BinOp(
            left=result.right,
            op=Add(),
            right=Call(
                func=Name(id='chr', ctx=Load()),
                args=[Constant(ord(x[index]))],
                keywords=[], starargs=None, kwargs=None
            )
        )
        index += 1
    return result

class Obfuscator(NodeTransformer):
    def __init__(self) -> None:
        super().__init__()
        self.indef = None
        self.import_module = {}
        self.global_var = {}
        self.attr_var = {}
        self.func = {}
        self.import_nodes = []
        self.attr_nodes = []
        self.var_nodes = []
        self.hashString = False

    def gc_attr(self, type_attr, rand_name, attr) -> Attribute:
        self.attr_var[type_attr] = rand_name
        type_ = type_attr.split('-')[0]
        if type_ not in self.global_var:
            getattr_name = self.global_var['getattr'] if 'getattr' in self.global_var else 'getattr'
            self.global_var[type_] = random_name()
            insert_node = Assign(
                targets=[Name(id=self.global_var[type_], ctx=Store())],
                value=Call(
                    func=Name(id=getattr_name, ctx=Load()), 
                    args=[Name(id='__builtins__', ctx=Load()), Constant(value=type_)], 
                    keywords=[]
                )
            )
            self.var_nodes.append(insert_node)
        type_ = self.global_var[type_]
        insert_node = Assign(
            targets=[
                Subscript(
                    value=Subscript(
                        value=Call(
                            func=Name(id=self.global_var['get_referents'], ctx=Load()),
                            args=[Attribute(value=Name(id=type_, ctx=Load()), attr='__dict__', ctx=Load())], 
                            keywords=[]
                        ),
                        slice=Constant(value=0), ctx=Load()
                    ),
                    slice=Constant(value=rand_name), ctx=Store()
                )
            ],
            value=Subscript(
                value=Subscript(
                    value=Call(
                        func=Name(id=self.global_var['get_referents'], ctx=Load()),
                        args=[Attribute(value=Name(id=type_, ctx=Load()), attr='__dict__', ctx=Load())], 
                        keywords=[]
                    ),
                    slice=Constant(value=0), ctx=Load()
                ),
                slice=Constant(value=attr), ctx=Store()
            )
        )
        self.attr_nodes.append(insert_node)

    def visit_Module(self, node: Module) -> Module:
        with open('enc_func.py', 'r', encoding='utf-8') as f:
            enc_func = eval(f.read())
        node.body = enc_func + node.body
        node.body = [self.visit(child) for child in node.body]
        node.body = [node.body[2]] + self.attr_nodes + node.body[3:]
        node.body = self.import_nodes + self.var_nodes + node.body
        global hash2str_name
        hash2str_name = self.global_var['hash2str']
        return node
        
    def visit_Import(self, node: Import):
        if node.names[0].name in self.import_module:
            return None
        name = node.names[0].name
        node.names[0].name = random_name()
        self.import_module[name] = node.names[0].name
        insert_node = Assign(
            targets=[Name(id=node.names[0].name, ctx=Store())],
            value=Call(
                func=Name(id='__import__', ctx=Load()),
                args=[
                    Constant(value=name),
                    Call(func=Name(id='globals', ctx=Load()), args=[], keywords=[], starargs=None, kwargs=None),
                    Call(func=Name(id='locals', ctx=Load()), args=[], keywords=[], starargs=None, kwargs=None),
                    List(elts=[], ctx=Load()),
                    Constant(value=0)
                ],
                keywords=[], starargs=None, kwargs=None
            )
        )
        self.import_nodes.append(insert_node)
        # print(f'Import: {name} -> {node.names[0].name}')
        return None
    
    def visit_Attribute(self, node: Attribute):
        rand_name = random_name()
        attr = node.attr
        if isinstance(node.value, Name):
            name_attr = f'{node.value.id}-{attr}'
            if node.value.id in self.import_module:
                if name_attr in self.global_var:
                    # print(f'Attribute: {node.value.id}.{attr} -> {self.global_var[name_attr]}')
                    return Name(id=self.global_var[name_attr], ctx=Load())
                getattr_name = self.global_var['getattr'] if 'getattr' in self.global_var else 'getattr'
                self.global_var[name_attr] = rand_name
                insert_node = Assign(
                    targets=[Name(id=rand_name, ctx=Store())],
                    value=Call(
                        func=Name(id=getattr_name, ctx=Load()), 
                        args=[
                            Name(id=self.import_module[node.value.id], ctx=Load()), 
                            Constant(value=attr)
                        ], 
                        keywords=[]
                    )
                )
                self.var_nodes.append(insert_node)
                # print(f'Attribute: {node.value.id}.{attr} -> {rand_name}')
                return Name(id=self.global_var[name_attr], ctx=Load())
            value_kind = [
                'bytes' if attr in dir(bytes) else None,
                'str' if attr in dir(str) else None,
                'int' if attr in dir(int) else None,
            ]
            if 'bytes' in value_kind:
                type_attr = f'bytes-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                    rand_name = self.attr_var[type_attr]
                else:
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
                    # print(f'Attribute: {node.value.id}.{attr} -> {node.value.id}.{rand_name}')
            if 'str' in value_kind:
                type_attr = f'str-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                    rand_name = self.attr_var[type_attr]
                else:
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
                    # print(f'Attribute: {node.value.id}.{attr} -> {node.value.id}.{rand_name}')
            if 'int' in value_kind:
                type_attr = f'int-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                    rand_name = self.attr_var[type_attr]
                else:
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
                    # print(f'Attribute: {node.value.id}.{attr} -> {node.value.id}.{rand_name}')
        elif isinstance(node.value, Constant):
            if isinstance(node.value.value, str):
                type_attr = f'str-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                elif attr in dir(str):
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
            elif isinstance(node.value.value, bytes):
                type_attr = f'bytes-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                elif attr in dir(bytes):
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
            elif isinstance(node.value.value, list):
                type_attr = f'list-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                elif attr in dir(list):
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
            elif isinstance(node.value.value, dict):
                type_attr = f'dict-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                elif attr in dir(dict):
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
            # print(f'Attribute: {node.value.value}.{attr} -> {node.value.value}.{node.attr}')
        elif isinstance(node.value, Call):
            value_kind = [
                'bytes' if attr in dir(bytes) else None,
                'str' if attr in dir(str) else None
            ]
            if 'bytes' in value_kind:
                type_attr = f'bytes-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                    rand_name = self.attr_var[type_attr]
                else:
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
                    # print(f'Attribute: {node.value}.{attr} -> {node.value}.{rand_name}')
            if 'str' in value_kind:
                type_attr = f'str-{attr}'
                if type_attr in self.attr_var:
                    node.attr = self.attr_var[type_attr]
                    rand_name = self.attr_var[type_attr]
                else:
                    self.gc_attr(type_attr, rand_name, attr)
                    node.attr = rand_name
                    # print(f'Attribute: {node.value}.{attr} -> {node.value}.{rand_name}')
        # elif 
        node.value = self.visit(node.value)
        return node
    
    def visit_FunctionDef(self, node: FunctionDef) -> FunctionDef:
        name = node.name
        rand_name = random_name()
        self.func[name] = {'name': rand_name}
        self.global_var[name] = rand_name
        node.name = rand_name
        func_args = {}
        for i in node.args.args:
            func_args[i.arg] = random_name()
            i.arg = func_args[i.arg]
        self.func[name]['args'] = func_args
        self.func[name]['local_var'] = {}
        self.indef = name
        node.body = [self.visit(child) for child in node.body]
        if self.indef == 'hash2str':
            self.hashString = True
        self.indef = None
        # print(f'FunctionDef: {name} -> {rand_name}')
        return node
    
    def visit_Name(self, node: Name) -> Name:
        name = node.id
        rand_name = random_name()
        if name in self.import_module:
            node.id = self.import_module[name]
        elif name in self.global_var:
            node.id = self.global_var[name]
        elif name in dir(__builtins__):
            if name == '__name__':
                return node
            getattr_name = self.global_var['getattr'] if 'getattr' in self.global_var else 'getattr'
            self.global_var[name] = rand_name
            insert_node = Assign(
                targets=[Name(id=rand_name, ctx=Store())], 
                value=Call(
                    func=Name(id=getattr_name, ctx=Load()), 
                    args=[
                        Name(id='__builtins__', ctx=Load()), 
                        Constant(value=name)
                    ], 
                    keywords=[]
                )
            )
            self.var_nodes.append(insert_node)
            node.id = rand_name
        elif self.indef is not None:
            if name in self.func[self.indef]['args']:
                node.id = self.func[self.indef]['args'][name]
            elif name in self.func[self.indef]['local_var']:
                node.id = self.func[self.indef]['local_var'][name]
            else:
                self.func[self.indef]['local_var'][name] = rand_name
                node.id = rand_name
        else:
            node.id = rand_name
            self.global_var[name] = rand_name
        # print(f'Name: {name} -> {node.id}')
        return node


class strObfuscator(NodeTransformer):
    def __init__(self) -> None:
        super().__init__()
        self.indef = None
        self.hashString = False

    def visit_FunctionDef(self, node: FunctionDef) -> FunctionDef:
        name = node.name
        self.indef = name
        node.body = [self.visit(child) for child in node.body]
        if self.indef == hash2str_name:
            self.hashString = True
        self.indef = None
        return node

    def visit_Str(self, node: Str):
        if self.indef == hash2str_name:
            return node
        s = node.s
        table = [lambda x: toChr(x)]
        if self.hashString:
            table.append(lambda x: Call(
                func=Name(id=hash2str_name, ctx=Load()),
                args=[Constant(value=str2hash(x))],
                keywords=[]
            ))
        match len(s):
            case 0:
                return node
            case _:
                if not self.hashString:
                    node = toChr(s)
                else:
                    node = Call(
                        func=Name(id=hash2str_name, ctx=Load()),
                        args=[Constant(value=str2hash(s))],
                        keywords=[]
                    )
        return node

class numObfuscator(NodeTransformer):
    def visit_Num(self, node: Num):
        xor_num = random.randint(1, 256)
        sub_num = random.randint(1, 256)
        return BinOp(
            left=BinOp(left=Num((node.n ^ xor_num) + sub_num),
                       op=Sub(), right=Num(n=sub_num)),
            op=BitXor(), right=Num(xor_num)
        )

if __name__ == '__main__':
    if len(sys.argv) > 1:
        file_name = sys.argv[1]
        file_name = os.path.basename(file_name)
        print(f"Begin obfuse {file_name}...")
    else:
        print("Usage: python obfuscate.py <file>")
        sys.exit(1)
    with open(file_name, 'r', encoding='utf-8') as f:
        tree = parse(f.read())
    obf = Obfuscator()
    tree = obf.visit(tree)
    obf = strObfuscator()
    tree = obf.visit(tree)
    obf_code = astor.to_source(tree)
    with open("obf_" + file_name, 'w') as f:
        f.write(obf_code)
    print(f"Obfuse {file_name} done!")
    print(f"Output file: obf_{file_name}")