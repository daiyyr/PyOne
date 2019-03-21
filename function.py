#-*- coding=utf-8 -*-
from app.utils import *


if __name__=='__main__':
    func=sys.argv[1]
    if len(sys.argv)>2:
        if sys.argv[-1]=='&':
            if len(sys.argv)>3:
                args=sys.argv[2:-1]
                eval(func+str(tuple(args)))
        else:
            args=sys.argv[2:]
            eval(func+str(tuple(args)))
    else:
        eval(func+'()')
