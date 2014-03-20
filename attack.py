import sys, subprocess, hashlib
import string
import math

##########################################
#######		MONTGOMERY				######
##########################################

def to_binary(x) :
	return bin(x)

# def to_limbs(x) :
# 	bin_mask = 18446744073709551615 #int repres of binary 1's x 64
# 	#result = bin_mask & x
# 	x = int(x, 16)
# 	limbs = []
# 	for i in range(0, get_limb_number(x)+1) :
# 		limbs.append(x & bin_mask)
# 		x = x >> 64
# 	return limbs

def get_ith_limb(x, i) :
	bin_mask = 18446744073709551615
	#x = int(x, 16)
	return (x >> 64 * i) & bin_mask

def get_limb_number(N) :
	return math.ceil(math.log( N, 2**64 ))

def Mont_Rho_Squared(b, N) :
	t = 1
	w = 64
	#print 2*get_limb_size(N)*w
	for i in range (0, int(2*get_limb_number(N)*w)) :
		t = (t + t) % N
	return t

def Mont_Omega(b, N) :
	t = 1
	w = 64
	for i in range(0, w - 1) :
		t *= t * N % b
	return -t % b

def Mont_Mul(b, x, y, N) :
	r = 0
	x0 = get_ith_limb(x, 0)
	omega = Mont_Omega(b, N)
	#print omega
	for i in range(0, int(get_limb_number(N))) :
		r0 = get_ith_limb(r, 0)
		yi = get_ith_limb(y, i)
		u = (r0 + yi * x0) * omega % b
		r = (r + yi * x + u * N)/b
	if (r >= N) :
		r -= N
	return r

def Mont_Exp (b, x, y, N) :
	rho_sq = Mont_Rho_Squared(b, N)
	#print rho_sq
	t_hat = Mont_Mul(b, 1, rho_sq, N)
	x_hat = Mont_Mul(b, x, rho_sq, N)
	#print x_hat
	y_bin = str(to_binary(y))[2:]
	#print y_bin
	for i in range(len(y_bin)-1, -1, -1) :
		#print i
		t_hat = Mont_Mul(b, t_hat, t_hat, N)
		if (y & (1<<i)) != 0 :
			t_hat = Mont_Mul(b, t_hat, x_hat, N)
	return Mont_Mul(b, t_hat, 1, N)


#########################################
#########		END MONT 	 ############
#########################################
def readFile(src) :
  file = open(src, "r")
  array = []
  for line in file:
    array.append(line)
  file.close
  return ( array[0], array[1]) #return N, e

def interact( c ) :
  target_in.write( "%s\n" % ( c ) ) ; target_in.flush()

  # Receive error code from attack target.
  m = ( target_out.readline().strip() )
  t = ( target_out.readline().strip() )
  
  return ( m, t )

def attack (c) :
  ( t, m) = interact(c)
  print ( t, m )

if ( __name__ == "__main__" ) :
  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  #(N, e) = readFile(sys.argv[2])
 

  # Execute a function representing the attacker.
  #attack(e)
  #N = '80955794bdb73369df4b8c1dbb3ffb5965b3494a787e369b4a80606d6ece157b3333950204abf9003ed9f601837b7d29d8e0a5e3f6ace7339ee1864bdae9c3ef92fe137c5ebc94768e6f3c82a6496131c1a64cfebff05aefd55c0749e4315de0599d9b3d2bdb530739035d01cb772fd05153be495252c98e1572ac725ab2531b'
  #print hex(Mont_Rho_Squared(2**64, N))
  #print hex(Mont_Omega(2**64, 12))
  #to_limb(N)
  #print to_limbs(N)
  x = 14777912434722484012795150747433197744767136897217162407762927865455435847145735686915331827545464755796807234471871479852466934757357239598392518626677060360692000372538879569563006291417336461597266487127830346581372131687317440322423575802518877104255558126974558449677855388857647750426674157655378030063 
  y = 82066906503981187431857367827616517547742026992296675269535396889324683244050948742697807615775012316882267807115314093017053946984947287322227475300115586985710753917221939474324908096704688427033412500308916929487658423364451145032970068348791689894471753550784886649253371303609895809157663585850520032959 
  #o = 3821265123607851245 
  N = 90294311424406673228338297200726006944631753630845809306519637227101667889745832477888085683126958592769170203506611034167697397910397535705315263098112563532540303944988972364693194890784306135883557032253343377823721157298262490305418829735604172267015074712472931277122629288704655390257429427388301857563 
  #result = 45433802701920380453411604806231273290811444884096114866758714947221099172975151096569118540500624694453477260546154752560809179159635158784131951809382948007794975525872262558587977950099953644268896784688508428777931074503177291622432277083167436003170271947767054363053386710537985790356233640292404824313
  print Mont_Exp(2**64, x, y, N)