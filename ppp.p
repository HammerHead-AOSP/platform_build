From: Doug Zongker <dougz@android.com>
Date: Fri, 22 May 2009 20:34:54 +0000 (-0700)
Subject: improve password entry for signing keys
X-Git-Tag: tegra-9.12.5-baseline~126
X-Git-Url: http://nv-tegra.nvidia.com/gitweb/?p=android%2Fplatform%2Fbuild.git;a=commitdiff_plain;h=8ce7c25e905bc14382359e1cd45d41832bcc7ffa

improve password entry for signing keys

Allow the user to set ANDROID_PW_FILE to the name of a file for
storing password keys.  When the tools need additional passwords, they
will rewrite this file and invoke the user's editor for the new
passwords to be added.  This allows passwords to be reused across
invocations of the signing tools, without making the user reenter them
every time.

Paranoid users can use a file stored in a ramdisk, or not use this
feature at all (the code will prompt for passwords in the ordinary way
when ANDROID_PW_FILE is not set).
---

diff --git a/tools/releasetools/common.py b/tools/releasetools/common.py
index a512ff8..51a6d8f 100644
--- a/tools/releasetools/common.py
+++ b/tools/releasetools/common.py
@@ -12,6 +12,7 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+import errno
 import getopt
 import getpass
 import os
@@ -132,13 +133,14 @@ def GetKeyPasswords(keylist):
   those which require them.  Return a {key: password} dict.  password
   will be None if the key has no password."""
 
-  key_passwords = {}
+  no_passwords = []
+  need_passwords = []
   devnull = open("/dev/null", "w+b")
   for k in sorted(keylist):
     # An empty-string key is used to mean don't re-sign this package.
     # Obviously we don't need a password for this non-key.
     if not k:
-      key_passwords[k] = None
+      no_passwords.append(k)
       continue
 
     p = subprocess.Popen(["openssl", "pkcs8", "-in", k+".pk8",
@@ -148,12 +150,13 @@ def GetKeyPasswords(keylist):
                          stderr=subprocess.STDOUT)
     p.communicate()
     if p.returncode == 0:
-      print "%s.pk8 does not require a password" % (k,)
-      key_passwords[k] = None
+      no_passwords.append(k)
     else:
-      key_passwords[k] = getpass.getpass("Enter password for %s.pk8> " % (k,))
+      need_passwords.append(k)
   devnull.close()
-  print
+
+  key_passwords = PasswordManager().GetPasswords(need_passwords)
+  key_passwords.update(dict.fromkeys(no_passwords, None))
   return key_passwords
 
 
@@ -278,3 +281,102 @@ def Cleanup():
       shutil.rmtree(i)
     else:
       os.remove(i)
+
+
+class PasswordManager(object):
+  def __init__(self):
+    self.editor = os.getenv("EDITOR", None)
+    self.pwfile = os.getenv("ANDROID_PW_FILE", None)
+
+  def GetPasswords(self, items):
+    """Get passwords corresponding to each string in 'items',
+    returning a dict.  (The dict may have keys in addition to the
+    values in 'items'.)
+
+    Uses the passwords in $ANDROID_PW_FILE if available, letting the
+    user edit that file to add more needed passwords.  If no editor is
+    available, or $ANDROID_PW_FILE isn't define, prompts the user
+    interactively in the ordinary way.
+    """
+
+    current = self.ReadFile()
+
+    first = True
+    while True:
+      missing = []
+      for i in items:
+        if i not in current or not current[i]:
+          missing.append(i)
+      # Are all the passwords already in the file?
+      if not missing: return current
+
+      for i in missing:
+        current[i] = ""
+
+      if not first:
+        print "key file %s still missing some passwords." % (self.pwfile,)
+        answer = raw_input("try to edit again? [y]> ").strip()
+        if answer and answer[0] not in 'yY':
+          raise RuntimeError("key passwords unavailable")
+      first = False
+
+      current = self.UpdateAndReadFile(current)
+
+  def PromptResult(self, current):
+    """Prompt the user to enter a value (password) for each key in
+    'current' whose value is fales.  Returns a new dict with all the
+    values.
+    """
+    result = {}
+    for k, v in sorted(current.iteritems()):
+      if v:
+        result[k] = v
+      else:
+        while True:
+          result[k] = getpass.getpass("Enter password for %s key> "
+                                      % (k,)).strip()
+          if result[k]: break
+    return result
+
+  def UpdateAndReadFile(self, current):
+    if not self.editor or not self.pwfile:
+      return self.PromptResult(current)
+
+    f = open(self.pwfile, "w")
+    os.chmod(self.pwfile, 0600)
+    f.write("# Enter key passwords between the [[[ ]]] brackets.\n")
+    f.write("# (Additional spaces are harmless.)\n\n")
+
+    first_line = None
+    sorted = [(not v, k, v) for (k, v) in current.iteritems()]
+    sorted.sort()
+    for i, (_, k, v) in enumerate(sorted):
+      f.write("[[[  %s  ]]] %s\n" % (v, k))
+      if not v and first_line is None:
+        # position cursor on first line with no password.
+        first_line = i + 4
+    f.close()
+
+    p = Run([self.editor, "+%d" % (first_line,), self.pwfile])
+    _, _ = p.communicate()
+
+    return self.ReadFile()
+
+  def ReadFile(self):
+    result = {}
+    if self.pwfile is None: return result
+    try:
+      f = open(self.pwfile, "r")
+      for line in f:
+        line = line.strip()
+        if not line or line[0] == '#': continue
+        m = re.match(r"^\[\[\[\s*(.*?)\s*\]\]\]\s*(\S+)$", line)
+        if not m:
+          print "failed to parse password file: ", line
+        else:
+          result[m.group(2)] = m.group(1)
+      f.close()
+    except IOError, e:
+      if e.errno != errno.ENOENT:
+        print "error reading password file: ", str(e)
+    return result
diff --git a/tools/releasetools/sign_target_files_apks b/tools/releasetools/sign_target_files_apks
index 844182d..9f393c8 100755
--- a/tools/releasetools/sign_target_files_apks
+++ b/tools/releasetools/sign_target_files_apks
@@ -141,7 +141,7 @@ def CheckSharedUserIdsConsistent(input_tf_zip, apk_key_map):
   going to be signed with the same key."""
 
   shared_user_apks = {}
-  maxlen = 0
+  maxlen = len("(unknown key)")
 
   for info in input_tf_zip.infolist():
     if info.filename.endswith(".apk"):
@@ -172,7 +172,7 @@ def CheckSharedUserIdsConsistent(input_tf_zip, apk_key_map):
   for user, keys in errors:
     print 'shared user id "%s":' % (user,)
     for key, apps in keys.iteritems():
-      print '  %-*s   %s' % (maxlen, key, apps[0])
+      print '  %-*s   %s' % (maxlen, key or "(unknown key)", apps[0])
       for a in apps[1:]:
         print (' ' * (maxlen+5)) + a
     print
