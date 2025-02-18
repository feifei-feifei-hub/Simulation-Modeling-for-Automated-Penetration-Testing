
# import pandas as pd
import numpy as np
import re
import os
import zipfile
import json
import csv
import pandas as pd
import ast


class Del_data:
    #读取表格中的数据，并删除重复的条目,将筛选后的数据保存为新的xlsx文件
    def __init__(self, path = './data_cve/all_20240825.xlsx'):
        self.path = path
        # self.all_cve,self.all_payload = self.data()
        # self.cve_server, self.cve_switch, self.cve_os, self.cve_database = self.classification()

    def data(self,outpath = './data_cve/new_all_20240825.xlsx'):
        #读取表格中的数据
        data = pd.read_excel(self.path,sheet_name='cve')
        #根据第一列的数据进行去重
        data = data.drop_duplicates(subset='漏洞号:cve',keep = 'first')
        #将数据保存为新的xlsx文件
        data.to_excel(outpath,index = False)

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
            if data["impact"] == []:
                #没有CVSS类型数据,直接设置所有属性均为null
                cve_name_detail["accessVector"] = "Null"
                self.accessVector.add("Null")
                cve_name_detail["baseScore"] = "Null"
                cve_name_detail["exploitabilityScore"] = "Null"
                cve_name_detail["obtainAllPrivilege"] = "Null"
                self.obtainAllPrivilege.add("Null")
                cve_name_detail["obtainUserPrivilege"] = "Null"
                self.obtainUserPrivilege.add("Null")
                cve_name_detail["obtainOtherPrivilege"] = "Null"
                self.obtainOtherPrivilege.add("Null")
                cve_name_detail["privilegesRequired"] = "Null"
                self.privilegesRequired.add("Null")
            elif "baseMetricV2" in data["impact"].keys():
                #CVSS2类型数据
                cve_name_detail["accessVector"] = data["impact"]["baseMetricV2"]["cvssV2"]["accessVector"] if "accessVector" in data["impact"]["baseMetricV2"]["cvssV2"].keys() else "Null"
                self.accessVector.add(data["impact"]["baseMetricV2"]["cvssV2"]["accessVector"]) if "accessVector" in data["impact"]["baseMetricV2"]["cvssV2"].keys() else self.accessVector.add("Null")
                cve_name_detail["baseScore"] = data["impact"]["baseMetricV2"]["cvssV2"]["baseScore"] if "baseScore" in data["impact"]["baseMetricV2"]["cvssV2"].keys() else "Null"
                cve_name_detail["exploitabilityScore"] = data["impact"]["baseMetricV2"]["exploitabilityScore"] if "exploitabilityScore" in data["impact"]["baseMetricV2"].keys() else "Null"
                cve_name_detail["obtainAllPrivilege"] = data["impact"]["baseMetricV2"]["obtainAllPrivilege"] if "obtainAllPrivilege" in data["impact"]["baseMetricV2"].keys() else "Null"
                self.obtainAllPrivilege.add(data["impact"]["baseMetricV2"]["obtainAllPrivilege"]) if "obtainAllPrivilege" in data["impact"]["baseMetricV2"].keys() else self.obtainAllPrivilege.add("Null")
                cve_name_detail["obtainUserPrivilege"] = data["impact"]["baseMetricV2"]["obtainUserPrivilege"] if "obtainUserPrivilege" in data["impact"]["baseMetricV2"].keys() else "Null"
                self.obtainUserPrivilege.add(data["impact"]["baseMetricV2"]["obtainUserPrivilege"]) if "obtainUserPrivilege" in data["impact"]["baseMetricV2"].keys() else self.obtainUserPrivilege.add("Null")
                cve_name_detail["obtainOtherPrivilege"] = data["impact"]["baseMetricV2"]["obtainOtherPrivilege"] if "obtainOtherPrivilege" in data["impact"]["baseMetricV2"].keys() else "Null"
                self.obtainOtherPrivilege.add(data["impact"]["baseMetricV2"]["obtainOtherPrivilege"]) if "obtainOtherPrivilege" in data["impact"]["baseMetricV2"].keys() else self.obtainOtherPrivilege.add("Null")
                cve_name_detail["privilegesRequired"] = "Null"
            elif "baseMetricV3" in data["impact"].keys():
                #CVSS3类型数据
                cve_name_detail["accessVector"] = data["impact"]["baseMetricV3"]["cvssV3"]["attackVector"] if "attackVector" in data["impact"]["baseMetricV3"]["cvssV3"].keys() else "Null"
                self.accessVector.add(data["impact"]["baseMetricV3"]["cvssV3"]["attackVector"]) if "attackVector" in data["impact"]["baseMetricV3"]["cvssV3"].keys() else self.accessVector.add("Null")
                cve_name_detail["privilegesRequired"] = data["impact"]["baseMetricV3"]["privilegesRequired"] if "privilegesRequired" in data["impact"]["baseMetricV3"].keys() else "Null"
                self.privilegesRequired.add(data["impact"]["baseMetricV3"]["privilegesRequired"]) if "privilegesRequired" in data["impact"]["baseMetricV3"].keys() else self.privilegesRequired.add("Null")

                cve_name_detail["baseScore"] = data["impact"]["baseMetricV3"]["cvssV3"]["baseScore"] if "baseScore" in data["impact"]["baseMetricV3"]["cvssV3"].keys() else "Null"
                cve_name_detail["exploitabilityScore"] = data["impact"]["baseMetricV3"]["exploitabilityScore"] if "exploitabilityScore" in data["impact"]["baseMetricV3"].keys() else "Null"
                cve_name_detail["obtainAllPrivilege"] = data["impact"]["baseMetricV3"]["obtainAllPrivilege"] if "obtainAllPrivilege" in data["impact"]["baseMetricV3"].keys() else "Null"
                self.obtainAllPrivilege.add(data["impact"]["baseMetricV3"]["obtainAllPrivilege"]) if "obtainAllPrivilege" in data["impact"]["baseMetricV3"].keys() else self.obtainAllPrivilege.add("Null")
                cve_name_detail["obtainUserPrivilege"] = data["impact"]["baseMetricV3"]["obtainUserPrivilege"] if "obtainUserPrivilege" in data["impact"]["baseMetricV3"].keys() else "Null"
                self.obtainUserPrivilege.add(data["impact"]["baseMetricV3"]["obtainUserPrivilege"]) if "obtainUserPrivilege" in data["impact"]["baseMetricV3"].keys() else self.obtainUserPrivilege.add("Null")
                cve_name_detail["obtainOtherPrivilege"] = data["impact"]["baseMetricV3"]["obtainOtherPrivilege"] if "obtainOtherPrivilege" in data["impact"]["baseMetricV3"].keys() else "Null"
                self.obtainOtherPrivilege.add(data["impact"]["baseMetricV3"]["obtainOtherPrivilege"]) if "obtainOtherPrivilege" in data["impact"]["baseMetricV3"].keys() else self.obtainOtherPrivilege.add("Null")
            #将数据写入excel文件
            header = list(cve_name_detail.keys())
            # datas.append(dic)
            with open('cve_ndss.csv', 'a', newline='',encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header)
                writer.writerow(cve_name_detail)
            return cve_name_detail
        
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
            return ["Null","Null","Null"]


class Read_data:
    def __init__(self, path = './data_cve/final0216_cve_type.xlsx'):
        self.path = path
        # all_cve,all_type,all_type_list = self.data()
    
    def data(self):
        #读取表格中的数据
        data = pd.read_excel(self.path,sheet_name='Sheet1')
        #将数据保存为字典
        all_cve = {}
        all_type = set()
        all_type_list = {}
        #逐行读取数据,并将数据保存为字典
        for i in range(len(data)):
            cve = data.iloc[i]
            cve_name = cve["漏洞号:cve"]
            all_cve[cve_name] = {}
            all_cve[cve_name]["type"] = cve["渗透目标分类:targetcategory"]
            all_cve[cve_name]["执行类型"] = cve["other"]
            if all_cve[cve_name]["type"] not in all_type:
                all_type_list[all_cve[cve_name]["type"]] = set()
            all_type.add(cve["渗透目标分类:targetcategory"])
            all_type_list[all_cve[cve_name]["type"]].add(cve_name)
            all_cve[cve_name]["cve_name_detail"] = NVD_data().get_cve_info(cve_name)
            all_cve[cve_name]["description"] = all_cve[cve_name]["cve_name_detail"]["description"]
            all_cve[cve_name]["cpe_match"] = all_cve[cve_name]["cve_name_detail"]["cpe_match"]
            all_cve[cve_name]["accessVector"] = all_cve[cve_name]["cve_name_detail"]["accessVector"]
            all_cve[cve_name]["baseScore"] = all_cve[cve_name]["cve_name_detail"]["baseScore"]
            all_cve[cve_name]["exploitabilityScore"] = all_cve[cve_name]["cve_name_detail"]["exploitabilityScore"]
            all_cve[cve_name]["obtainAllPrivilege"] = all_cve[cve_name]["cve_name_detail"]["obtainAllPrivilege"]
            all_cve[cve_name]["obtainUserPrivilege"] = all_cve[cve_name]["cve_name_detail"]["obtainUserPrivilege"]
            all_cve[cve_name]["obtainOtherPrivilege"] = all_cve[cve_name]["cve_name_detail"]["obtainOtherPrivilege"]
            all_cve[cve_name]["privilegesRequired"] = all_cve[cve_name]["cve_name_detail"]["privilegesRequired"]
            all_cve[cve_name]["EPSS"] = EPSS_data().get_cve_score(cve_name)
            all_cve[cve_name]["EPSS_score"] = all_cve[cve_name]["EPSS"][1]
            if all_cve[cve_name]["baseScore"] == "Null":
                all_cve[cve_name]["baseScore"] = 5
            if all_cve[cve_name]["EPSS_score"] == "Null":
                all_cve[cve_name]["EPSS_score"] = 0.5
                
            all_cve[cve_name]["Final_score"] = 0.7*float(all_cve[cve_name]["baseScore"] )+ 0.3*float(all_cve[cve_name]["EPSS_score"])
            #将 all_cve 保存为excel文件
            all_cve[cve_name]["affectedversion"] = self.extract_product_version(all_cve[cve_name]["cpe_match"])

        df = pd.DataFrame.from_dict(all_cve, orient='index')
        df.to_excel('/root/feifei/8_network_generator/data_cve/all_cve_cvss_epss.xlsx', index_label='CVE_ID')
        all_type_ = list(all_type)
        with open('/root/feifei/8_network_generator/data_cve/all_type.json', 'w', encoding='utf-8') as f:
            json.dump(all_type_, f, ensure_ascii=False, indent=4)
        all_type_list_ = list(all_type_list)
        with open('/root/feifei/8_network_generator/data_cve/all_type_list.json', 'w', encoding='utf-8') as f:
            json.dump(all_type_list_, f, ensure_ascii=False, indent=4)
        return all_cve,all_type,all_type_list
    def extract_product_version(self,cpe_list,):
        result = []
        if type(cpe_list) == str:   
            cpe_list = cpe_list.replace('\n', '').replace(' ', '')
            cpe_list = ast.literal_eval(cpe_list)
        if len(cpe_list) == 0:
            return [("*",'0.0.0')]
        else:
            for cpe in cpe_list:
                # 拆分 CPE 字符串
                fields = cpe.split(':')
                
                # 提取产品和版本
                product = fields[4]  # 第4个字段是产品
                version = fields[5]  # 第5个字段是版本
                
                # 如果版本未指定，替换为 0.0.0
                if version == '*' or not version:
                    version = '0.0.0'
                
                # 将（产品，版本）对添加到结果列表
                result.append((product, version))
        return result
    def all_cve_type(self,file_path = "/root/feifei/8_network_generator/data_cve/all_cve_cvss_epss.xlsx"):
        all_cve = {}
        all_cve_type = {}
        try:
            df = pd.read_excel(file_path)
            for index, row in df.iterrows():
                cve_id = row['CVE_ID']  # 获取 CVE_ID 作为键
                values = row.drop('CVE_ID').to_dict()  # 其他内容作为值

                # 处理可能为列表的字段
                for key, value in values.items():
                    if isinstance(value, str) and value.startswith('[') and value.endswith(']'):
                        # 将字符串形式的列表转换为实际的列表
                        values[key] = eval(value)

                # 将 CVE_ID 和其他内容存入字典
                all_cve[cve_id] = values
                if all_cve[cve_id]["type"] not in all_cve_type.keys():
                    all_cve_type[all_cve[cve_id]["type"]] = set()
                all_cve_type[all_cve[cve_id]["type"]].add(cve_id)
            for key in all_cve_type.keys():
                all_cve_type[key] = list(all_cve_type[key])
            with open('/root/feifei/8_network_generator/data_cve/all_cve_type.json', 'w',encoding='utf-8') as f:
                json.dump(all_cve_type, f, ensure_ascii=False, indent=4)
            print(f"字典已成功保存为 JSON 文件: {file_path}")
        except Exception as e:
            print(f"保存 JSON 文件时发生错误: {e}")


    def read_all_type_list(self,file_path = '/root/feifei/8_network_generator/data_cve/all_cve_type.json'):
        eng_all_type_list = {}
        eng_all_type_list["firewall"] = []
        eng_all_type_list["switch"] = []
        eng_all_type_list["soft"] = []
        eng_all_type_list["remote"] = []
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                data = json.load(file)  # 将 JSON 文件内容加载为字典
                for key in data.keys():
                    if key == "/操作系统/Windows":
                        eng_all_type_list["os_windows"] = data[key]
                    elif key == "/操作系统/Linux":
                        eng_all_type_list["os_linux"] = data[key]
                    elif key == "/操作系统/Unix":
                        eng_all_type_list["os_unix"] = data[key]
                    elif key == "/操作系统/Mac":
                        eng_all_type_list["os_mac"] = data[key]
                    elif key == "/操作系统/iOS":
                        eng_all_type_list["os_ios"] = data[key]
                    elif key == "/Web":
                        eng_all_type_list["web"] = data[key]
                    elif key == "/防火墙" or key == "/防御设备" or key == "/邮件防火墙":
                        for m in data[key]:
                            eng_all_type_list["firewall"].append(m)
                    elif key == "/路由器" or key == "/交换机":
                        for m in data[key]:
                            eng_all_type_list["switch"].append(m)
                    elif key == "/数据库":
                        eng_all_type_list["database"] = data[key]
                    elif key == "/服务器":
                        eng_all_type_list["server"] = data[key]
                    elif key == "/防御组件" or key == "/应用软件" or key == "/应用软件管理系统" or key == "/组件/Java" or key == "/组件/Php":
                        for m in data[key]:
                            eng_all_type_list["soft"].append(m)
                    elif key == "/应用软件/Linux":
                        eng_all_type_list["soft_os_linux"] = data[key]
                    elif key == "/应用软件/Windows":
                        eng_all_type_list["soft_os_windows"] = data[key]
                    elif key == "/应用软件/Unix":
                        eng_all_type_list["soft_os_unix"] = data[key]
                    elif key == "/应用软件/Mac":
                        eng_all_type_list["soft_os_mac"] = data[key]
                    elif key == "/域漏洞":
                        eng_all_type_list["domain"] = data[key]
                    elif key == "/远程访问" or key == "/中间件":
                        for m in data[key]:
                            eng_all_type_list["remote"].append(m)
                with open('/root/feifei/8_network_generator/data_cve/eng_all_type_list.json', 'w', encoding='utf-8') as f:
                    json.dump(eng_all_type_list, f, ensure_ascii=False, indent=4)
                return eng_all_type_list
        except FileNotFoundError:
            print(f"文件未找到: {file_path}")
        except json.JSONDecodeError:
            print(f"文件不是有效的 JSON 格式: {file_path}")
        except Exception as e:
            print(f"读取文件时发生错误: {e}")
        
            




if __name__ == '__main__':
    Read_data().read_all_type_list()
    # EPSS_data().get_cve_score("CVE-2021-25676")


    # Del_data().data()
    # NVD_data().get_files()
    # NVD_data().get_cve_info("CVE-2022-24734")

