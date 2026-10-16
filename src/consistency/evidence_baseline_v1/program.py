"""Bounded data-only interpreter for Provider-supplied AppWorld programs.

NEVER eval/exec the program, call APIs, import its modules or read task answers.
API calls consume observed *delivered* values, deriving next arguments from the
actual instruction and prior observations. Unsupported syntax stops explicitly.
"""
import ast
from copy import deepcopy
from dataclasses import dataclass
import datetime as dt
import operator
import re


class Unsupported(ValueError): pass
class StopProgram(Exception): pass
class ContinueLoop(Exception): pass
class BreakLoop(Exception): pass
class ReturnValue(Exception):
    def __init__(self, value): self.value = value


@dataclass
class Ref:
    path: str


@dataclass
class Method:
    value: object
    name: str


class Interpreter:
    def __init__(self, children, clock=None, max_steps=150000):
        self.children = children
        self.clock = clock
        self.max_steps, self.steps, self.index = max_steps, 0, 0
        self.calls, self.functions, self.env = [], {}, {}
        self.env.update(apis=Ref('apis'), requester=Ref('requester'))

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps: raise Unsupported('program_step_budget')

    def bounded(self, value):
        if isinstance(value, int) and value.bit_length() > 4096:
            raise Unsupported('program_integer_budget')
        if isinstance(value, (list, tuple, dict, set, range, str, bytes)) and len(value) > 200000:
            raise Unsupported('program_value_budget')
        return value

    def attr(self, value, name):
        if name.startswith('_'): raise Unsupported('private_attribute')
        if isinstance(value, Ref): return Ref(value.path + '.' + name)
        # Numeric date/time properties are values, not bound methods. Treating
        # .year as Method made legal branch conditions silently evaluate false.
        if isinstance(value, (dt.date, dt.time)):
            properties = {'year', 'month', 'day'} if isinstance(value, dt.date) else set()
            if isinstance(value, (dt.datetime, dt.time)):
                properties |= {'hour', 'minute', 'second', 'microsecond', 'fold'}
            if name in properties:
                return getattr(value, name)
            if not callable(getattr(value, name, None)) and name not in {'add', 'subtract', 'start_of', 'format'}:
                raise Unsupported('unregistered_datetime_attribute:' + name)
        if isinstance(value, (dict, list, str, dt.datetime, dt.date, dt.time, re.Match)):
            return Method(value, name)
        raise Unsupported('attribute_type')

    def call(self, fn, args, kwargs, node, env):
        self.tick()
        if isinstance(fn, Ref):
            path = fn.path
            if path.startswith('apis.') and path.count('.') == 2:
                if args: raise Unsupported('positional_api_arguments')
                row = {'tool':path[5:], 'arguments':deepcopy(kwargs), 'line':node.lineno,
                       'expression':ast.get_source_segment(self.code, node), 'ordinal':self.index}
                self.calls.append(row)
                if self.index >= len(self.children): raise Unsupported('missing_child_observation')
                observed = self.children[self.index]
                self.index += 1
                row['observed_id'] = observed.get('call_ref')
                if 'delivered' not in observed: raise Unsupported('missing_child_delivery')
                if observed.get('delivered_exception'): raise Unsupported('observed_child_exception')
                return deepcopy(observed['delivered'])
            if path.startswith('DateTime.') or path.startswith('pendulum.'):
                method = path.split('.')[-1]
                if method == 'now':
                    if not self.clock: raise Unsupported('missing_environment_clock')
                    return dt.datetime.fromisoformat(self.clock).replace(tzinfo=None)
                if method == 'parse': return dt.datetime.fromisoformat(args[0].replace('Z', '+00:00')).replace(tzinfo=None)
                if method == 'strptime': return dt.datetime.strptime(*args)
                if method == 'time': return dt.time(*args,**kwargs)
                raise Unsupported('datetime_method:' + method)
            if path == 're.search':
                # No unbounded regex evaluation on untrusted patterns/contents.
                if len(args[0]) > 150 or len(args[1]) > 10000 or re.search(r'\\[1-9]|\([^)]*[+*][^)]*\)[+*{]', args[0]):
                    raise Unsupported('regex_budget_or_nested_quantifier')
                return re.search(*args, **kwargs)
            raise Unsupported('unregistered_call:' + path)
        if isinstance(fn, Method):
            value, name = fn.value, fn.name
            allowed = {
                str: {'split','rsplit','join','strip','rstrip','lstrip','replace','startswith','endswith','lower','upper','format'},
                dict: {'get','items','keys','values','pop','copy','update','setdefault'},
                list: {'append','extend','pop','index','count','copy'},
                dt.datetime: {'strftime','time','date','isoformat','replace'},
                dt.date: {'strftime','isoformat'}, dt.time: {'strftime','isoformat','replace'},
                re.Match: {'group','groups'},
            }
            if isinstance(value, dt.datetime):
                if name == 'format':
                    # Bounded Pendulum English month-name profile used by the
                    # public programs; do not approximate arbitrary tokens/locales.
                    if args != ['MMMM'] or kwargs.get('locale', 'en') != 'en' or set(kwargs) - {'locale'}:
                        raise Unsupported('datetime_format_profile')
                    return ('January', 'February', 'March', 'April', 'May', 'June',
                            'July', 'August', 'September', 'October', 'November', 'December')[value.month - 1]
                if name in ('add','subtract'):
                    if set(kwargs) - {'days','hours','minutes','seconds','weeks'}: raise Unsupported('datetime_units')
                    delta = dt.timedelta(**kwargs)
                    return value + delta if name == 'add' else value - delta
                if name == 'start_of' and args == ['day']:
                    return value.replace(hour=0, minute=0, second=0, microsecond=0)
                if name == 'start_of' and args == ['month']:
                    return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                if name == 'start_of' and args == ['year']:
                    return value.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            if isinstance(value, dt.time) and name in ('add','subtract'):
                if args or set(kwargs) - {'hours','minutes','seconds','microseconds'}:
                    raise Unsupported('time_units')
                delta=dt.timedelta(**kwargs)
                origin=dt.datetime.combine(dt.date(1970,1,1),value)
                return (origin+delta if name=='add' else origin-delta).time()
            if name not in allowed.get(type(value), set()): raise Unsupported('unregistered_method:' + name)
            if name == 'format' and isinstance(value, str) and re.search(r'\{[^}]*[.\[]', value):
                raise Unsupported('format_attribute_access')
            return self.bounded(getattr(value, name)(*args, **kwargs))
        if isinstance(fn, ast.FunctionDef):
            names = [a.arg for a in fn.args.args]
            if len(args) > len(names) or set(kwargs) - set(names): raise Unsupported('function_arguments')
            local = dict(env)
            for name, value in zip(names, args): local[name] = value
            local.update(kwargs)
            if any(n not in local for n in names): raise Unsupported('missing_function_argument')
            try: self.block(fn.body, local)
            except ReturnValue as returned: return returned.value
            return None
        raise Unsupported('not_callable')

    def expression(self, n, env):
        self.tick()
        if isinstance(n, ast.Constant): return n.value
        if isinstance(n, ast.Name):
            if n.id not in env: raise Unsupported('unknown_name:' + n.id)
            return env[n.id]
        if isinstance(n, (ast.List, ast.Tuple, ast.Set)):
            values = [self.expression(e, env) for e in n.elts]
            return tuple(values) if isinstance(n, ast.Tuple) else set(values) if isinstance(n, ast.Set) else values
        if isinstance(n, ast.Dict):
            out = {}
            for k,v in zip(n.keys,n.values):
                if k is None: out.update(self.expression(v,env))
                else: out[self.expression(k,env)] = self.expression(v,env)
            return out
        if isinstance(n, ast.Attribute): return self.attr(self.expression(n.value,env), n.attr)
        if isinstance(n, ast.Slice): return slice(*(self.expression(v,env) if v else None for v in (n.lower,n.upper,n.step)))
        if isinstance(n, ast.Subscript): return self.expression(n.value,env)[self.expression(n.slice,env)]
        if isinstance(n, ast.UnaryOp):
            value = self.expression(n.operand,env)
            if isinstance(n.op,ast.Not): return not value
            if isinstance(n.op,ast.USub): return -value
            if isinstance(n.op,ast.UAdd): return +value
            raise Unsupported('unary_operator')
        if isinstance(n, ast.BinOp):
            a,b = self.expression(n.left,env), self.expression(n.right,env)
            if isinstance(n.op,ast.Mult) and isinstance(a,(str,list,tuple)) and isinstance(b,int) and len(a)*b>200000:
                raise Unsupported('multiplication_budget')
            if isinstance(n.op,ast.Mult) and isinstance(b,(str,list,tuple)) and isinstance(a,int) and len(b)*a>200000:
                raise Unsupported('multiplication_budget')
            ops={ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul,ast.Div:operator.truediv,ast.FloorDiv:operator.floordiv,ast.Mod:operator.mod}
            if type(n.op) not in ops: raise Unsupported('binary_operator')
            return self.bounded(ops[type(n.op)](a,b))
        if isinstance(n, ast.BoolOp):
            for item in n.values:
                value = self.expression(item,env)
                if isinstance(n.op,ast.And) and not value: return value
                if isinstance(n.op,ast.Or) and value: return value
            return value
        if isinstance(n, ast.Compare):
            a = self.expression(n.left,env)
            ops={ast.Eq:operator.eq,ast.NotEq:operator.ne,ast.Lt:operator.lt,ast.Gt:operator.gt,ast.LtE:operator.le,ast.GtE:operator.ge,
                 ast.In:lambda a,b:a in b,ast.NotIn:lambda a,b:a not in b,ast.Is:operator.is_,ast.IsNot:operator.is_not}
            for op,right in zip(n.ops,n.comparators):
                b=self.expression(right,env)
                if isinstance(a, (Method, Ref)) or isinstance(b, (Method, Ref)):
                    raise Unsupported('unevaluated_reference_comparison')
                if type(op) not in ops: raise Unsupported('comparison_operator')
                if not ops[type(op)](a,b): return False
                a=b
            return True
        if isinstance(n, ast.IfExp): return self.expression(n.body if self.expression(n.test,env) else n.orelse,env)
        if isinstance(n,(ast.ListComp,ast.DictComp,ast.SetComp,ast.GeneratorExp)):
            def generate(index,local):
                if index == len(n.generators):
                    yield (self.expression(n.key,local),self.expression(n.value,local)) if isinstance(n,ast.DictComp) else self.expression(n.elt,local)
                    return
                gen=n.generators[index]
                if gen.is_async: raise Unsupported('async_comprehension')
                for value in self.expression(gen.iter,local):
                    self.tick(); nested=dict(local);self.assign(gen.target,value,nested)
                    if all(self.expression(c,nested) for c in gen.ifs): yield from generate(index+1,nested)
            values=generate(0,dict(env))
            if isinstance(n,ast.GeneratorExp): return values
            out=dict(values) if isinstance(n,ast.DictComp) else set(values) if isinstance(n,ast.SetComp) else list(values)
            return self.bounded(out)
        if isinstance(n,ast.JoinedStr):
            out=[]
            for value in n.values:
                if isinstance(value,ast.Constant):out.append(value.value)
                else:
                    result=self.expression(value.value,env)
                    if value.conversion == 114:result=repr(result)
                    elif value.conversion == 115:result=str(result)
                    elif value.conversion != -1:raise Unsupported('format_conversion')
                    out.append(format(result,self.expression(value.format_spec,env) if value.format_spec else ''))
            return self.bounded(''.join(out))
        if isinstance(n,ast.Call):
            args=[];kwargs={}
            for arg in n.args:
                if isinstance(arg,ast.Starred):args.extend(self.expression(arg.value,env))
                else:args.append(self.expression(arg,env))
            for kw in n.keywords:
                if kw.arg is None:kwargs.update(self.expression(kw.value,env))
                else:kwargs[kw.arg]=self.expression(kw.value,env)
            if isinstance(n.func,ast.Name) and n.func.id not in env:
                safe={'next':next,'len':len,'range':range,'zip':zip,'enumerate':enumerate,'dict':dict,'list':list,'set':set,'tuple':tuple,
                      'int':int,'float':float,'str':str,'bool':bool,'sum':sum,'min':min,'max':max,'abs':abs,'round':round,'sorted':sorted,
                      'any':any,'all':all,'print':lambda *a,**k:None}
                if n.func.id not in safe:raise Unsupported('unregistered_builtin:' + n.func.id)
                if n.func.id == 'range' and len(range(*args))>200000:raise Unsupported('range_budget')
                return self.bounded(safe[n.func.id](*args,**kwargs))
            return self.call(self.expression(n.func,env),args,kwargs,n,env)
        raise Unsupported('syntax:' + type(n).__name__)

    def assign(self,n,value,env):
        if isinstance(n,ast.Name):env[n.id]=value
        elif isinstance(n,(ast.Tuple,ast.List)):
            values=list(value)
            if len(values)!=len(n.elts):raise Unsupported('unpack_length')
            for child,val in zip(n.elts,values):self.assign(child,val,env)
        elif isinstance(n,ast.Subscript):self.expression(n.value,env)[self.expression(n.slice,env)]=value
        else:raise Unsupported('assignment_target')

    def block(self,nodes,env):
        for n in nodes:
            self.tick()
            if isinstance(n,ast.ImportFrom):
                permitted={'appworld.collections.apis':{'ApiCollection'}, 'appworld.requester':{'Requester'},
                           'appworld.common.datetime':{'DateTime','VanillaDateTime','pendulum'}}
                if n.module not in permitted or n.level:raise Unsupported('import_module')
                for alias in n.names:
                    if alias.name not in permitted[n.module]:raise Unsupported('import_name')
                    env[alias.asname or alias.name]=Ref('DateTime' if alias.name=='VanillaDateTime' else alias.name)
            elif isinstance(n,ast.Import):
                for alias in n.names:
                    if alias.name!='re':raise Unsupported('import_module')
                    env[alias.asname or alias.name]=Ref('re')
            elif isinstance(n,ast.FunctionDef):
                if n.decorator_list:raise Unsupported('decorated_function')
                env[n.name]=n
            elif isinstance(n,ast.Assign):
                value=self.expression(n.value,env)
                for target in n.targets:self.assign(target,value,env)
            elif isinstance(n,ast.AugAssign):
                synthetic=ast.BinOp(left=n.target,op=n.op,right=n.value)
                self.assign(n.target,self.expression(synthetic,env),env)
            elif isinstance(n,ast.Expr):self.expression(n.value,env)
            elif isinstance(n,ast.If):self.block(n.body if self.expression(n.test,env) else n.orelse,env)
            elif isinstance(n,ast.For):
                broke=False
                for value in self.expression(n.iter,env):
                    self.tick();self.assign(n.target,value,env)
                    try:self.block(n.body,env)
                    except ContinueLoop:continue
                    except BreakLoop:broke=True;break
                if not broke:self.block(n.orelse,env)
            elif isinstance(n,ast.Return):raise ReturnValue(self.expression(n.value,env) if n.value else None)
            elif isinstance(n,ast.Continue):raise ContinueLoop()
            elif isinstance(n,ast.Break):raise BreakLoop()
            elif isinstance(n,ast.Pass):pass
            elif isinstance(n,ast.Delete):
                for target in n.targets:
                    if isinstance(target,ast.Name):del env[target.id]
                    elif isinstance(target,ast.Subscript):del self.expression(target.value,env)[self.expression(target.slice,env)]
                    else:raise Unsupported('delete_target')
            else:raise Unsupported('statement:' + type(n).__name__)

    def run(self,code):
        self.code=code
        try:
            if len(code)>200000:raise Unsupported('source_budget')
            tree=ast.parse(code)
            if sum(1 for _ in ast.walk(tree))>20000:raise Unsupported('ast_budget')
            self.block(tree.body,self.env)
            return {'complete':True,'calls':self.calls,'consumed':self.index,'steps':self.steps,'reason':None}
        except (Unsupported, KeyError, IndexError, TypeError, ValueError, StopIteration, AttributeError, ZeroDivisionError, RecursionError, SyntaxError, OverflowError) as exc:
            return {'complete':False,'calls':self.calls,'consumed':self.index,'steps':self.steps,
                    'reason':str(exc) if isinstance(exc,Unsupported) else type(exc).__name__}


def interpret(code, children, clock=None): return Interpreter(children, clock).run(code)
