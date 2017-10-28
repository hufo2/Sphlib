import re
import os
import glob

'''
This script converts sphlib java source files to c#
It would not work for generic conversions, but the sphlib
hashing code only needs relatively few edits, as we can assume
that all integer variables/cast can be converted to unsigned.

It currently works for: Blake, Groestl, JH, Skein
Other algorithms probably only require minimal adjustements.

Note: overflow checks MUST be disabled when compiling the c#
source code. Easier that wrapping all methods within an unchecked
bloc ;)
'''
os.chdir("src");
javaFiles = glob.glob("*.java")
for javafname in javaFiles:
  csharpfname = "../"+javafname[0:-5]+".cs";
  classname = javafname[0:-5]
  print csharpfname
  javaf = open(javafname)
  csharpf = open(csharpfname, "w")
  isinterface = False
  for line in javaf.readlines():
    maindecl = False
    line = line.rstrip("\n");
    #print "<<<"+line+">>>"
    if line == "package fr.cryptohash;":
      csharpf.write("using System;\n\n")
      csharpf.write("namespace CryptoHash\n")
      line = "{"
    elif line.strip().startswith("abstract class"):
      line = "public " + line
      line = line.replace(" extends "," : ")
      line = line.replace(" implements "," : ")
      maindecl = True
    elif line.strip().startswith("public class") or line.strip().startswith("public abstract class"):
      line = line.replace(" extends "," : ")
      line = line.replace(" implements "," : ")
      maindecl = True
    elif line.strip().startswith("public interface"):
      isinterface = True
      maindecl = True
    elif line.strip() == "super();":
      continue #line = '		base();';
    elif line == '	'+classname+"()":
      line = '	public '+classname+"()"
    elif line.endswith("static {"):
      line = line[0:-1] + classname + "() {"
    else: # generic lines
      if isinterface and line.startswith("	public "):
        line = "	" + line[8:]
      #line = line.replace("static final","static readonly")
      line = line.replace("update(byte in)","update(byte @in)")
      line = line.replace(" = in;"," = @in;")
      line = line.replace("System.arraycopy", "Array.Copy")
      #line = line.replace(".length", ".Length")
      line = re.sub(r'^	(protected|public|private) static final(.*)\((.*)\)$',r'	\1 static \2(\3)', line)
      line = re.sub(r'^	static (protected|public|private) final(.*)\((.*)\)$',r'	\1 static \2(\3)', line)
      line = re.sub(r'^	(protected|public|private) static final(.*)$',r'	\1 static readonly \2', line)
      line = re.sub(r'^	(protected|public|private) final',r'	\1', line)
      line = re.sub(r'\blong\b','ulong', line)
      line = re.sub(r'\bint\b','uint', line)
      line = re.sub(r'\bString\b','string', line)
      line = re.sub(r'\b([a-zA-Z0-9_]+)\.length\b',r'(uint)\1.Length', line)
      line = re.sub(r'\bsuper\.\b','base.', line)
      line = re.sub(r'\bout\b','@out', line)
      line = re.sub(r'\(([a-zA-Z0-9_]+) >>> ([0-9]+)\)',r'(\1 >> \2)', line)
      line = re.sub(r'\(\(ulong\)\(([^\(\)&]+) & (0x[a-fA-F0-9]+)\) << ([0-9]+)\)',r'((((ulong)(\1)) & \2UL) << \3)', line)
      line = re.sub(r'\(ulong\)\(([^\(\)&]+) & (0x[a-fA-F0-9]+)\)',r'(((ulong)(\1)) & \2UL)', line)
      line = re.sub(r'\((buf\[[^\(\)&]+\]) & (0xFF)L\)',r'((ulong)\1 & \2UL)', line)
      line = re.sub(r'\(buf\[off([ +0-9]*)\] & (0xFF)\)',r'((uint)buf[(int)off\1] & \2U)', line)
      line = re.sub(r'\(uint\)\(x\[([0-9]+)\] >>> ([0-9]+)\)',r'(uint)(x[\1] >> \2)', line)
      line = re.sub(r'\(\(uint\)x\[([0-9]+)\] >>> ([0-9]+)\)',r'((uint)x[\1] >> \2)', line)
      line = re.sub(r'\(\(uint\)([a-zA-Z0-9_]+) >>> ([0-9]+)\)',r'((uint)\1 >> \2)', line)
      line = re.sub(r'\(ulong\)([a-zA-Z0-9_]+) \^ -(0x[0-9A-F]+)L\b',r'(ulong)\1 ^ unchecked((ulong)-\2L)', line)
      line = re.sub(r'\(ulong\)(\([\w +]+\)) \^ -(0x[0-9A-F]+)L\b',r'(ulong)\1 ^ unchecked((ulong)-\2L)', line)
      line = line.replace("(x >>> (64 - n))", "(((ulong)x) >> (64 - (int)n))")
      line = line.replace("(x << n)", "(x << (int)n)")
      line = line.replace("(x >>> n)", "(x >> (int)n)")
      line = line.replace("(x << (32 - n))", "(x << (int)(32 - n))")
      line = line.replace("(x << (64 - n))", "(x << (int)(64 - n))")
      line = line.replace("((ulong)x >>> (64 - (uint)n))", "(((ulong)x) >> (64 - (int)n))")
      line = line.replace("buf[off", "buf[(int)off")
      line = re.sub(r'(\(\(h\[..\] & c\)) << (n\) \| \(\(h\[..\]) >>> (n\) \& c\))',r'\1 << (int)\2 >> (int)\3', line)
      line = line.replace('encodeBELong(bc >>> 55,','encodeBELong(bc >> 55,')
      line = line.replace(" >>> ", " >> ") # all remaining right shifts
      line = line.replace("(uint)0xFFFFFFFFFFFFFC00L", "(ulong)0xFFFFFFFFFFFFFC00UL") # all remaining right shifts
      line = line.replace("(t0 & ~0x3FF)", "(t0 & ~0x3FFUL)") # all remaining right shifts
      line = re.sub(r'\(bcount == 0\) \? ([0-9]+) : ([0-9]+)\b',r'(bcount == 0) ? \1U : \2U', line)
      line = re.sub(r'	abstract (ulong\[\] getIV|u\w+\[\] getInitVal|Skein\w+Core dup())\(\);',r'	public abstract \1();', line)
      line = re.sub(r'	(ulong\[\] getIV|u\w+\[\] getInitVal|Skein\w+Core dup())\(\)',r'	public override \1()', line)
      if classname != "Digest" and classname != "DigestEngine":
        line = re.sub(r'^	(protected|public|private) (uint getBlockLength|void engineReset|void doPadding|void doInit|void processBlock|string toString|uint getDigestLength|Digest copy)\((.*)\)$',r'	\1 override \2(\3)', line)
      if classname == "SkeinSmallCore" or classname == "SkeinBigCore":
	    line = re.sub(r'^	(protected|public|private) override ',r'	\1 ',line)
    if maindecl and classname == "DigestEngine":
      line += """
	public abstract uint getDigestLength();
	public abstract Digest copy();
	public abstract uint getBlockLength();
	public abstract string toString();
	""";
    if maindecl and (classname == "SkeinSmallCore" or classname == "SkeinBigCore"):
      line += """
	public abstract uint getDigestLength();
	""";
	# choose any indent style
    line = line.replace('	','  ');
    csharpf.write(line+"\n");
  csharpf.write("}\n")
  csharpf.close();
  javaf.close();

#raw_input("end");