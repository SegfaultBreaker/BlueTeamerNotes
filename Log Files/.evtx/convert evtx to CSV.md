## Here is how you can use all your evtx file that you could retrieved for analysis, gathered and parsed in one csv format file.

### First
You'll need to download this tool : https://download.ericzimmermanstools.com/net9/EvtxECmd.zip (if you dont trust the link, just visit the website)

Once it's downloaded you just need to use the tool (you can use powershell / cmd) and following this command : 

.\EvtxECmd.exe -d "path to logs" --csv "path where to save result csv" --csvf filename.csv (like the following picture, attention don't forget to be in the path of the exe file previously downloaded)

![image](https://github.com/user-attachments/assets/d2980720-5e01-4a17-9bb2-369d488fac2c)

Once it's finished you should have only one .CSV file on the folder that you mentionned

### After the first step

Ok you have a CSV file but would you open it in excel ? Naaaaa too boring. You'll need to have a second tool called "Timeline Explorer". It could be compared as the Wireshark for CSV files (in the context of evtx) 

You can downloaded via this link : https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip

Once it's downloaded import your CSV in a the tool it should like this !

![{A83905DC-E7FA-4678-A5B7-E3A5D3288E4D}](https://github.com/user-attachments/assets/af2f40da-278b-4413-898e-f0f2b55ecbdb)
(I cannot show you everything because it's too bigger)

#### Filters

You can do some filter, searching for terms etc. For filters you only need to right click on the column and do filter editor

![image](https://github.com/user-attachments/assets/5ec37254-4c31-4b93-bdd0-b64ed51ee91e)

You'll have like a querry builder that will be displayed 
![{516CBF34-8B3F-4066-AAC2-F7D650F7BC35}](https://github.com/user-attachments/assets/96113116-6112-4528-a121-1a16811793d5)

You can of course add condition etc by using

![image](https://github.com/user-attachments/assets/6bc6bbd3-7850-4b99-8d1c-221f8e01f315)
