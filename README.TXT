
System Management RAM analysis tool. 

**************************************************************************

For more information about this project please read the following article:

http://blog.cr4.sh/2016/10/exploiting-ami-aptio-firmware.html


To use full capabilities of this tool you need to install UEFIDump (https://github.com/LongSoft/UEFITool/releases/tag/A32), ida-efiutils (https://github.com/snare/ida-efiutils) and edit corresponding variables in smram_parse.py code.

This tool was tested only with 6 generation Intel NUC firmware based on AMI Aptio V code base.


FEATURES:

  * SMRAM and SMST address information
  * Loaded SMM drivers list
  * SMM protocols list
  * SMI entry address for each CPU
  * SW SMI handlers list
  * Root SmiHandlerRegister() handlers list
  * Child SmiHandlerRegister() handlers list


USAGE:

  $ smram_parse.py <SMRAM_dump> [flash_image_dump]

  Output example: https://raw.githubusercontent.com/Cr4sh/smram_parse/master/EXAMPLE.TXT


Written by:
Dmytro Oleksiuk (aka Cr4sh)

cr4sh0@gmail.com
http://blog.cr4.sh

