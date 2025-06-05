## Here is how you can use all your evtx file that you could retrieved for analysis gathered and parsed in csv format.

### First
You'll need to download this tool : https://download.ericzimmermanstools.com/net9/EvtxECmd.zip (if you dont trust the link, just visit the website)

Once it's downloaded you just need to use the tool (you can use powershell / cmd) and following this command : 

.\EvtxECmd.exe -d "path to logs" --csv "path where to save result csv" --csvf filename.csv (like the following picture, attention don't forget to be in the path of the exe file previously downloaded)

![image](https://github.com/user-attachments/assets/d2980720-5e01-4a17-9bb2-369d488fac2c)

Once it's finished you should have only one .CSV file on the folder that you mentionned
