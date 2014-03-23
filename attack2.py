import sys, subprocess, hashlib, math, os, time

def interactD(c) :
  if len(c) != 256:
    c = c.zfill(256)
  
  targetD_in.write( "%s\n" % (c) ) ; targetD_in.flush()
  t = targetD_out.readline().strip()
  m = targetD_out.readline().strip()
  
  return (t, m)

def interactR(c,N,d):
  if len(c) != 256:
    c = c.zfill(256)
    N = N.zfill(256)
    d = d.zfill(256)

  targetR_in.write( "%s\n%s\n%s\n" % (c,N,d) ) ; targetR_in.flush()
  t = targetR_out.readline().strip()
  m = targetR_out.readline().strip()

  return (t, m)

def getLimbN(x,limb_number):
  mask = 18446744073709551615 # = 2^64
  return (x >> 64 * limb_number) & mask

# def getLimbN(x,limb_number):
#   bin_x = bin(x)[2:]
#   for i in range(len(bin_x),1024):
#     bin_x = "0" + bin_x
#     # bin_x.zfill(1024)
#   size = 1024
#   return int((bin_x[size-(limb_number*64+64):size-(limb_number*64)]),2)


def calcOmega(modN,base):
  t = 1
  NmodBase = getLimbN(modN,0)
  for i in range (1,64):
    t = (t * t * NmodBase) % base
  return 2**64 - t

def calcRhoSquared(modN,base):
  rhoSquare = 1
  ln = int(math.ceil(math.log(modN,base)))

  for i in range(0,2*ln*64):
    rhoSquare = (rhoSquare + rhoSquare) % modN

  return rhoSquare

def montMul(x,y,omega,modN,base):
  result = 0
  ln = int(math.ceil(math.log(modN,base)))
  u = 0

  for i in range(0,ln):
    r0 = getLimbN(result,0)
    x0 = getLimbN(x,0)
    yi = getLimbN(y,i)
    u = ((r0 + yi*x0)*omega) % base

    tmp = modN * u
    result += tmp
    tmp = x*yi
    result += tmp

    result = result / base

  if (result>modN):
    flag = True
    result = result - modN
  else:
    flag = False

  return result, flag

# def montExp(x,y,N,base):
#   omega, x_hat, resultUnset, unsetFlag, res_hat, setFlag = montExpInitialiseLoop(x,y,N,base)
#   bin_y = bin(y)[2:]

#   # res_hat = resultSet

#   for i in range(1,len(bin_y)):
#     if (i!=len(bin_y)-1):
#       resultUnset, unsetKReductionFlag, resultSet, setKReductionFlag = montExpLastIteration(res_hat,x_hat,omega,base,N)
#       if (bin_y[i] == "1"):
#         res_hat = resultSet
#       else:
#         res_hat = resultUnset
#     else:
#       if (bin_y[i] == "1"):
#         res_hat, flag = montMul(res_hat,x_hat,omega,N,base)
#   result, flag = montMul(res_hat,1,omega,N,base)

#   print result


def montExpLastIteration(res_hat,x_hat,omega,base,modN):
  resultUnset, unsetKReductionFlag = montMul(res_hat,res_hat,omega,modN,base) #this is for the unset k bit
  res_hat, flag = montMul(res_hat,x_hat,omega,modN,base)
  resultSet, setKReductionFlag = montMul(res_hat,res_hat,omega,modN,base)

  return resultUnset, unsetKReductionFlag, resultSet, setKReductionFlag

def montExpInitialiseLoop(x,y,modN,base,omega):
  x = x % modN
  rhoSquare = calcRhoSquared(modN,base)

  res_hat, flag = montMul(1,rhoSquare,omega,modN,base)
  x_hat, flag = montMul(x,rhoSquare,omega,modN,base)

  res_hat, flag = montMul(res_hat,res_hat,omega,modN,base)

  # first iteration
  res_hat, flag = montMul(res_hat,x_hat,omega,modN,base)
  res_hat, flag = montMul(res_hat,res_hat,omega,modN,base)


  resultUnset, unsetFlag, res_hat, setFlag = montExpLastIteration(res_hat,x_hat,omega,base,modN)

  return x_hat, resultUnset, unsetFlag, res_hat, setFlag

# def montExp(x,y,modN,base):
#   tmp2 = x % modN
#   tmp = 1
#   omega = calcOmega(modN,base)
#   rhoSquare = calcRhoSquared(modN,base)

#   res_hat, flag = montMul(tmp,rhoSquare,omega,modN,base)
#   x_hat, flag = montMul(tmp2,rhoSquare,omega,modN,base)

#   bin_y = bin(y)[2:]
#   BITS = len(bin_y)

#   result, flag = montMul(res_hat,res_hat,omega,modN,base)

#   for i in range(0,BITS):
#     if(bin_y[i] == "1"):
#       res_hat, flag = montMul(result,x_hat,omega,modN,base)
#     else:
#       res_hat = result

#     result, flag = montMul(res_hat,res_hat,omega,modN,base)

#   #when it executes for the current i-1 bits do one more iteration for a set and unset extra bit
#   result, unsetKReductionFlag = montMul(res_hat,res_hat,omega,modN,base) #this is for the unset k bit
#   res_hat, flag = montMul(result,x_hat,omega,modN,base)
#   result, setKReductionFlag = montMul(res_hat,res_hat,omega,modN,base)

#   # result, flag = montMul(res_hat,tmp,omega,modN)

#   return result, unsetKReductionFlag, setKReductionFlag

def randomCiphertexts(n):
  cipherTexts = []
  for i in range(0,n):
    cipherTexts.append(os.urandom(64).encode('hex'))

  return cipherTexts

def getAverages(M1,M2,M3,M4):
  a1 = reduce(lambda x, y: x + y, M1) / float(len(M1))
  a2 = reduce(lambda x, y: x + y, M2) / float(len(M2))
  a3 = reduce(lambda x, y: x + y, M3) / float(len(M3))
  a4 = reduce(lambda x, y: x + y, M4) / float(len(M4))

  return a1,a2,a3,a4

def attack(N_string, e_string):
  N = int(N_string,16)
  e = int(e_string,16)

  # c = os.urandom(64).encode('hex')

  # (t, m) = interactD(c)
  # print m
  # d = hex(int("1111101011110010111010111010100111101001111010111110100001111001",2))[2:-1]
  # print d
  # (t, m) = interactR(c,N_string,d)
  # print m

  base = 2**64

  cipherTexts = randomCiphertexts(10000)
  timings = []
  resultUnset = [0]*(len(cipherTexts))
  resultSet = [0]*(len(cipherTexts))
  omega = [0]*(len(cipherTexts))
  x_hat = [0]*(len(cipherTexts))
  res_hat = [0]*(len(cipherTexts))

  for i in range(0, len(cipherTexts)):
    timings.append(int(interactD(cipherTexts[i])[0]))

  omega = calcOmega(N,base)

  k = "1"

  print time.ctime()

  for j in range(0,64):
    print k
    M1 = []
    M2 = []
    M3 = []
    M4 = []
    for i in range(0,len(cipherTexts)):
      if (i%1000==0):
        print "cipheretext" + str(i)
      if (j==0):
        x_hat[i], resultUnset[i], unsetKReductionFlag, resultSet[i], setKReductionFlag = montExpInitialiseLoop(int(cipherTexts[i],16),int(k,2),N,base,omega)
      else:
        if (k[len(k)-1] == "1"):
          res_hat[i] = resultSet[i]
        else:
          res_hat[i] = resultUnset[i]
        resultUnset[i], unsetKReductionFlag, resultSet[i], setKReductionFlag = montExpLastIteration(res_hat[i],x_hat[i],omega,base,N)

      if (setKReductionFlag):
        M1.append(timings[i])
      elif (not(setKReductionFlag)):
        M2.append(timings[i])
      if (unsetKReductionFlag):
        M3.append(timings[i])
      else:
        M4.append(timings[i])
      # print "cipheretext " + str(i)
    (a1,a2,a3,a4) = getAverages(M1,M2,M3,M4)

    diff1 = a1-a2
    diff2 = a3-a4

    if (diff1>diff2): # if diff1 > diff2 means that mean(M1) > mean(M2)
      k = k + "1"
    else:             # if diff1 < diff2 means that mean(M1) = mean(M2) and mean(M3) > mean(M4)
      k = k + "0"
    print "diff1 = " + str(diff1)
    print "diff2 = " + str(diff2)


if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.
  targetD = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  targetR = subprocess.Popen( args   = sys.argv[ 2 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  targetD_out = targetD.stdout
  targetD_in  = targetD.stdin

  targetR_out = targetR.stdout
  targetR_in  = targetR.stdin

  # montExp(2,5,5,2**64)

  f = open(sys.argv[3], 'r')
  N = f.readline()
  e = f.readline()

  attack(N,e)