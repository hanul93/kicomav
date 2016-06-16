# -*- coding:utf-8 -*-

"""
Copyright (C) 2013-2014 Nurilab.

Author: Kei Choi(hanul93@gmail.com)

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
"""

import random
import base64
import marshal

#---------------------------------------------------------------------
# Euclid's GCD Algorithm
#---------------------------------------------------------------------
def gcd(a, b) :
    if b == 0 :
        return a;
    else :
        return gcd(b, (a % b))
	
def ExtEuclid(a, b) :
    i = -1
    R = []
    Q = []
    X = []
    Y = []
    
    i += 1
    R.append(a)     # -1
    R.append(b)     #  0
    
    Q.append(0)     # -1
    Q.append(0)     #  0
    
    X.append(1)     # -1
    X.append(0)     #  0
    
    Y.append(0)     # -1
    Y.append(1)     #  0
        
    i = 2
    try :
        while 1 :
            R.append(R[i-2] % R[i-1])
            Q.append(R[i-2] / R[i-1])
            
            if R[i] == 0 :
                d = R[i-1]
                x = X[i-1]
                y = Y[i-1]
                break
                
            X.append(X[i-2] - (Q[i] * X[i-1]))
            Y.append(Y[i-2] - (Q[i] * Y[i-1]))
            
            i += 1
    except :
        pass
	    
    if x < 0 :
        x += b
    if y < 0 :
        y += b

    return d, x, y

#---------------------------------------------------------------------
# RSA Algorithm
#---------------------------------------------------------------------
def Get_kq(n) :
    k = 0
    q = 0

    t = n - 1
    b_t = bin(t)
    
    for i in range(len(b_t)-1, -1, -1) :
        if b_t[i] == '0' :
            k += 1
        else :
            break
    
    q = t >> k
    return (k, q)
    
def MR(n) :
    composite = 0    # composite number
    inconclusive = 0 # May be prime number

    k, q = Get_kq(n)
    if k == 0 :
        return 0 # Not prime

    for i in range(10) : # 10 times Test
        a = int(random.uniform(2, n)) # 1 < a < n
        #if (a ** q) % n == 1 :
        if pow(a, q, n) == 1 :
            inconclusive += 1
            continue
       
        t = 0
        for j in range(k) :
            #if (a ** (2*j*q)) % n == n-1 :
            if pow(a, (2*j*q), n) == n-1 :
                inconclusive += 1
                t = 1

        if t == 0 :        
            composite += 1

    if inconclusive >= 6 :
        return 1

def GenNumber(GenBit) :
    random.seed()

    b = ''
    for i in range(GenBit-1) :
        b += str(int(random.uniform(1, 10)) % 2)
    b += '1'

    return int(b, 2)

def GenPrime(GenBit) :
    while 1 :
        p = GenNumber(GenBit)
        if MR(p) == 1 :
            break

    return p

def GetED(n) :
    while 1 :
        t = int(random.uniform(2, 1000))
        d, x, y = ExtEuclid(t, n)
        if d == 1 :
            return t, x

def GenD(e, n) :
    while 1 :
        t = int(random.uniform(2, 1000))
        d, x, y = ExtEuclid(t*e, n)
        if d == 1 :
            return t, x



#---------------------------------------------------------------------
# Create Keys
#---------------------------------------------------------------------
debug = False # Debug Mode

def main() :
    p = GenPrime(128) # generating a prime number (128bit)
    q = GenPrime(128) # generating a prime number (128bit)

    # print 'p    :', hex(p)
    # print 'q    :', hex(q)

    n  = p * q
    # print 'n    :', hex(n)

    Qn = (p-1) * (q-1)

    # print 'Q(n) :', hex(Qn) #, len(bin(Qn)[2:])

    e, d = GetED(Qn)
    # print 'e    :', hex(e)
    # print 'd    :', hex(d)


    PU = [e, n]
    PR = [d, n]

    # print 'PU   :', PU # public key
    # print 'PR   :', PR # private key

    pu_data = base64.b64encode(marshal.dumps(PU))
    pr_data = base64.b64encode(marshal.dumps(PR))
    
    try :
        open('key.pkr', 'wt').write(pu_data)
        open('key.skr', 'wt').write(pr_data)
    except :
        print 'ERROR'
        exit(0)
        
    print '[*] Make key : key.prk, key.skr'   
    
    if debug : 
        plantext = 'Hello, World!' # Plan text (max 30 bytes)

        plantext_ord = 0
        for i in range(len(plantext)) :
            plantext_ord |= ord(plantext[i]) << (i*8)

        print 'plan :', hex(plantext_ord)
        e = pow(plantext_ord, PR[0], PR[1]) # encrypt by private key
        print 'enc  :', hex(e)

        d = pow(e, PU[0], PU[1]) # decrypt by public key
        print 'dec  :', hex(d)

        s = ''
        for i in range(32) :
            b = d & 0xff
            d >>= 8
            s += chr(b)
        print 'plan text :', s



if __name__ == '__main__' :
    main()
