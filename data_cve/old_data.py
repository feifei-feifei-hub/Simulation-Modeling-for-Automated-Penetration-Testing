
# import pandas as pd
import numpy as np
import re
import os
import zipfile
import json
import csv
import pandas as pd
# import openpyxl  # 使用pd.read_excel中需要保证openpyxl库已安装，但可以不导入。 				#读Excel数据用
# 文件的作用，从final0216_cve_type.xlsx能够获取CVE名称、类型
# 从NVD-Database-master.zip中获取CVE的详细信息，包括描述、cpe_match、cvss2、cvss3等
# 从EPSS.csv中获取CVE的分数和百分比
# 定义一个函数，生成最终的CSV文件，包括CVE名称、类型、描述、cpe_match、cvss2、cvss3、EPSS分数、百分比

class Classify_cve:
    def __init__(self):
        self.path = './data_cve/final0216_cve_type.xlsx'
        self.cve_server, self.cve_switch, self.cve_os, self.cve_database = self.classification()



class Read_data:
    def __init__(self, path = './data_cve/fei_cve_20230728.xlsx'):
        self.path = path
        self.all_cve,self.all_payload = self.data()
        self.cve_server, self.cve_switch, self.cve_os, self.cve_database = self.classification()

    def data(self):
        data = pd.read_excel(self.path,sheet_name='cve')
        #	data是Excel里的数据
        # print(len(data))
        # print(data.iloc[2,2])
        # h = data.iloc[2,2].split(",")
        # print(type(h))
        data_array = np.array(data)
        data_list =data_array.tolist()
        print(type(data_list))
        print(data_list)
        all_cve = {}
        for i in range(len(data)):
            all_cve[data.iloc[i,1]] = {}
            all_cve[data.iloc[i,1]]["id"] = data.iloc[i,0]
            all_cve[data.iloc[i,1]]["targetcategory"] = data.iloc[i,2].split(",")
            all_cve[data.iloc[i,1]]["targetname"] = data.iloc[i,3].split(",")
            all_cve[data.iloc[i,1]]["type"] = data.iloc[i,6]
            all_cve[data.iloc[i,1]]["rule"] = data.iloc[i,10].split(",")
            all_cve[data.iloc[i,1]]["availableexp"] = data.iloc[i,11].split(",")
            all_cve[data.iloc[i,1]]["availablePayload"] = str(data.iloc[i,12]).split(",")
            all_cve[data.iloc[i,1]]["hazardrank"] = data.iloc[i,14]
            #以下是对受影响版本的生成
            num = data.iloc[i,4]
            num5 = re.sub(u"([^\u0030-\u0039\u002e])", " ", str(num))
            i1 = re.split('\s+',num5)
            ls1=[x for x in i1 if x!='' and x != '.']
            ls1_ = []
            for j in ls1:
                if '.' in list(j):
                    ls1_.append(j)
            all_cve[data.iloc[i,1]]["affectedversion"] = ls1_
        # print(all_cve['CVE-2017-12635']["targetcategory"])
        # print(all_cve)

        data_payload = pd.read_excel(self.path,sheet_name='payload')
        all_payload = {}
        for i in range(len(data_payload)):
            all_payload[data_payload.iloc[i,0]] = {}
            all_payload[data_payload.iloc[i,0]]["type"] = data_payload.iloc[i,2]
            all_payload[data_payload.iloc[i,0]]["direction"] = data_payload.iloc[i,3]
            all_payload[data_payload.iloc[i,0]]["score"] = float(data_payload.iloc[i,5])

        #print(type(all_payload["2uJznvpMVbRE7N5Uf9J3UX"]["score"]))

        data_help = pd.read_excel(self.path,sheet_name='ATT')
        # print(data_help.iloc[15,17])
        all_help = {}
        for i in range(len(data_help)):
            all_help[data_help.iloc[i,1]] = {}
            all_help[data_help.iloc[i,1]]["score"] = float(data_help.iloc[i,17])
        # print(all_help)
        for i in all_cve:
            # print(i)
            # print(all_cve[i])
            if i in all_help.keys():
                all_cve[i]["score"] = all_help[i]["score"]
            else:
                all_cve[i]["score"] = 1.0
        # print (all_cve)
        # print(all_cve["CVE-2021-25646"])
        # print(all_help["CVE-2021-25646"])
        return all_cve, all_payload
    
    def classification(self):
        #对漏洞进行一定的分类
        cve_server = {}#针对节点中的软件可能有的漏洞，“应用”、“web”、“协议
        cve_switch = {}#针对交换机可能有的漏洞。“中间件”
        cve_os = {}#针对操作系统可能有的漏洞，“操作系统”
        cve_database = {}#针对数据库可能有的漏洞，“大数据”
        
        for i in self.all_cve:
            # print(self.all_cve[i]['targetcategory'])
            if "中间件" in self.all_cve[i]['targetcategory']:
                cve_switch[i] = self.all_cve[i]
            if "操作系统" in self.all_cve[i]['targetcategory']:
                cve_os[i] = self.all_cve[i]
            if "数据库" in self.all_cve[i]['targetcategory'] or "大数据" in self.all_cve[i]['targetcategory']:
                cve_database[i] = self.all_cve[i]
            if "应用" in self.all_cve[i]['targetcategory'] or "Web" in self.all_cve[i]['targetcategory'] or "协议" in self.all_cve[i]['targetcategory'] or "框架" in self.all_cve[i]['targetcategory']:
                cve_server[i] = self.all_cve[i]
        
        return cve_server,cve_switch,cve_os,cve_database
    
class Del_data:
    #读取表格中的数据，并删除重复的条目,将筛选后的数据保存为新的xlsx文件
    def __init__(self, path = './data_cve/all_20240825.xlsx'):
        self.path = path
        # self.all_cve,self.all_payload = self.data()
        # self.cve_server, self.cve_switch, self.cve_os, self.cve_database = self.classification()

    def data(self):
        #读取表格中的数据
        data = pd.read_excel(self.path,sheet_name='cve')
        #根据第一列的数据进行去重
        data = data.drop_duplicates(subset='漏洞号:cve',keep = 'first')
        #将数据保存为新的xlsx文件
        data.to_excel('./data_cve/new_all_20240825.xlsx',index = False)

#从NVD中获取数据
class NVD_data:
    def __init__(self,path = "/root/feifei/8_network_generator/data_cve",outpath = "/root/feifei/8_network_generator/data_nvd", zipfilename = "NVD-Database-master.zip"):
        self.path = path
        self.outpath = outpath
        self.zipfilename  = zipfilename
        filename = self.path + '/' +self.zipfilename
        self.zfile = zipfile.ZipFile(filename, 'r')
        #看看这几个值有几种情况
        self.accessVector = set()
        # self.exploitabilityScore = set()
        self.obtainAllPrivilege = set()
        self.obtainUserPrivilege = set()
        self.obtainOtherPrivilege = set()
        self.privilegesRequired = set()
    
    # def get_files(self):
    #     #获取文件夹下所有文件的名称
    #     for filepath,dirnames,filenames in os.walk(self.path):
    #         for filename in filenames:
    #             print (filename)
    # #根据单个CVE名称获取他的相关属性
    def get_cve_info(self,cve_name):
        #读取csv文件中的数据，并判断是否存在该cve_name的数据
        csv_reader = csv.reader(open('cve_ndss.csv'))
        df = pd.read_csv('cve_ndss.csv',encoding="utf-8")
        all_cve = df['cve_id'].tolist()
        if cve_name in all_cve:
            ind = all_cve.index(cve_name)
            return df.iloc[ind]
        else:
            file_path = self.path
            year = cve_name.split("-")[1]
            filename = self.zipfilename.split(".")[0] + '/' + year + '/' +cve_name + '.json'
            # 判断文件是否存在与self.outpath文件夹下
            if not os.path.exists(self.outpath + '/' + filename):
                self.zfile.extract(filename, path=self.outpath)
            #读取json文件中的内容，并转化为字典，基于字典进行操作
            data = json.load(open(self.outpath + '/' + filename))
            #从字典中抽取数据
            cve_name_detail = {}
            cve_name_detail["cve_id"] = cve_name
            cve_name_detail["description"] = data["cve"]["description"]["description_data"][0]["value"]
            cve_name_detail["cpe_match"] = []
            for i in data["configurations"]["nodes"]:
                if "cpe_match" in i.keys():
                    for j in i["cpe_match"]:
                        cve_name_detail["cpe_match"].append(j["cpe23Uri"])
                    # cve_name_detail["cpe_match"].append(i["cpe_match"]) 
            if "baseMetricV2" in data["impact"].keys():
                #CVSS2类型数据
                cve_name_detail["accessVector"] = data["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]
                self.accessVector.add(data["impact"]["baseMetricV2"]["cvssV2"]["accessVector"])
                cve_name_detail["baseScore"] = data["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                cve_name_detail["exploitabilityScore"] = data["impact"]["baseMetricV2"]["exploitabilityScore"]
                cve_name_detail["obtainAllPrivilege"] = data["impact"]["baseMetricV2"]["obtainAllPrivilege"]
                self.obtainAllPrivilege.add(data["impact"]["baseMetricV2"]["obtainAllPrivilege"])
                cve_name_detail["obtainUserPrivilege"] = data["impact"]["baseMetricV2"]["obtainUserPrivilege"]
                self.obtainUserPrivilege.add(data["impact"]["baseMetricV2"]["obtainUserPrivilege"])
                cve_name_detail["obtainOtherPrivilege"] = data["impact"]["baseMetricV2"]["obtainOtherPrivilege"]
                self.obtainOtherPrivilege.add(data["impact"]["baseMetricV2"]["obtainOtherPrivilege"])
                cve_name_detail["privilegesRequired"] = "Null"
            elif "baseMetricV3" in data["impact"].keys():
                #CVSS3类型数据
                cve_name_detail["accessVector"] = data["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]
                self.accessVector.add(data["impact"]["baseMetricV3"]["cvssV3"]["attackVector"])
                cve_name_detail["privilegesRequired"] = data["impact"]["baseMetricV3"]["privilegesRequired"]
                self.privilegesRequired.add(data["impact"]["baseMetricV3"]["privilegesRequired"])

                cve_name_detail["baseScore"] = data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                cve_name_detail["exploitabilityScore"] = data["impact"]["baseMetricV3"]["exploitabilityScore"]
                cve_name_detail["obtainAllPrivilege"] = data["impact"]["baseMetricV3"]["obtainAllPrivilege"]
                self.obtainAllPrivilege.add(data["impact"]["baseMetricV3"]["obtainAllPrivilege"])
                cve_name_detail["obtainUserPrivilege"] = data["impact"]["baseMetricV3"]["obtainUserPrivilege"]
                self.obtainUserPrivilege.add(data["impact"]["baseMetricV3"]["obtainUserPrivilege"])
                cve_name_detail["obtainOtherPrivilege"] = data["impact"]["baseMetricV3"]["obtainOtherPrivilege"]
                self.obtainOtherPrivilege.add(data["impact"]["baseMetricV3"]["obtainOtherPrivilege"])
            #将数据写入excel文件
            header = list(cve_name_detail.keys())
            # datas.append(dic)
            with open('cve_ndss.csv', 'a', newline='',encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writerow(cve_name_detail)
            return cve_name_detail
        
    def get_cve_info(self,cve_name_list):
        #读取csv文件中的数据，首先是生成所有CVE的类型
        pass
    def classfiy_cve(self):
        #读取文件，根据CVE的类型进行分类，并获取所有的cve信息，保存到文件中
        pass
        
class EPSS_data:
    def __init__(self,path = "/root/feifei/8_network_generator/data_cve/",outpath = "/root/feifei/8_network_generator/data_nvd", filename = "EPSS.csv"):
        #EPSS数据只有cve和分数和百分比
        self.path = path
        self.outpath = outpath
        self.file = path + filename
    def get_cve_score(self,cve_name):
        #读取csv.gz文件中的数据，并判断是否存在该cve_name的数据
        df = pd.read_csv(self.file)
        # df.drop([0])
        all_cve = df['cve'].tolist()
        if cve_name in all_cve:
            ind = all_cve.index(cve_name)
            return df.iloc[ind].tolist()
        else:
            return ["null","null","null"]

#将CVE根据关键词划分为不同的类型
class Classify_cve:
    def __init__(self):
        self.path = './data_cve/new_all_20240825.xlsx'
        self.cve_server, self.cve_switch, self.cve_os, self.cve_database = self.classification()






        
            
        
      
    
if __name__ == '__main__':
    # EPSS_data().get_cve_score("CVE-2021-25676")


    # Del_data().data()
    # NVD_data().get_files()
    NVD_data().get_cve_info("CVE-2022-24734")

#     cve_server,cve_switch,cve_os,cve_database = Read_data().classification()
#     # print("cve_server",cve_server.keys())
#     # print("cve_switch",cve_switch.keys())
#     # print("cve_os",cve_os.keys())
#     # print("cve_database",cve_database.keys())
#     cve = Read_data()
#     print("cve_server",cve.all_cve)








    


