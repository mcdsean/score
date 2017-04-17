import os, re, zipfile
import py_common

FVDL_NAME = "audit.fvdl"


class Xml(object):
    def __init__(self, cwe_id_padded, cwe_num, tc_type, true_false, tc_lang, new_xml_name, scan_data_file):
        self.cwe_id_padded = cwe_id_padded
        self.cwe_num = cwe_num
        self.tc_type = tc_type

        self.tc_count = ''  # tc_count
        self.num_of_hits = ''  # num_of_hits
        self.percent_hits = ''  # percent_hits
        self.tc_path = ''  # tc_path
        self.tc_lang = tc_lang


        self.true_false = true_false
        self.new_xml_name = new_xml_name
        self.scan_data_file = scan_data_file

        print('SCAN DATA FILE---', self.scan_data_file)


class Xmls(object):
    def __init__(self, source_path, dest_path, tool_name):
        self.source_path = source_path
        self.dest_path = dest_path
        self.tool_name = tool_name

        # raw file produced by tool
        self.scan_data_files = []
        # list of xml projects
        self.xml_projects = []

        # create or clean xml dir
        self.create_xml_dir()
        # get the xml info and create copies
        self.get_xml_info(self.scan_data_files)
        self.get_test_case_path(self.scan_data_files)

    def create_xml_dir(self):
        # create, or empty, 'xmls' folder
        #
        # Note: Deleting entire folder and then re-creating it immediately sometimes conflicts
        # with anti-virus sortware and cannot always release handles quick enough, so the entire
        # parent folder is not deleted, only the files withing it. This prevents this problem
        #
        if not os.path.exists(self.dest_path):
            py_common.print_with_timestamp("The path \"" + self.dest_path + "\" does not exist")
            py_common.print_with_timestamp("creating directory \"" + self.dest_path + "\"")
            os.makedirs(self.dest_path)
        else:
            py_common.print_with_timestamp(self.dest_path + " already exists. Cleaning before use...")
            fileList = os.listdir(self.dest_path)
            for fileName in fileList:
                # os.remove(self.dest_path + "//" + fileName)
                os.remove(os.path.join(self.dest_path, fileName))

        # fortify files are not in standard xml format
        if self.tool_name == 'fortify':
            self.scan_data_files = py_common.find_files_in_dir(self.source_path, '.*?\.fpr$')
        else:
            self.scan_data_files = py_common.find_files_in_dir(self.source_path, '.*?\.xml$')

    def copy_xml_file(self, scan_data_file, new_xml_name):

        if self.tool_name == 'fortify':
            # self.extract_fvdl_from_fpr(scan_data_file, self.dest_path)

            # fortify .fpr files need unzipped to get the xml
            myzip = zipfile.ZipFile(scan_data_file, mode='r')
            myzip.extract(FVDL_NAME, path=self.dest_path)
            myzip.close()

        # format xml name
        tool_path_to_xml = os.path.join(self.dest_path, FVDL_NAME)
        new_path_to_xml = os.path.join(self.dest_path, new_xml_name)
        # create fresh xml name
        os.rename(tool_path_to_xml, new_path_to_xml)

    def get_xml_info(self, scan_data_files):

        for scan_data_file in scan_data_files:

            # get cwe number from project name
            match = re.search('CWE\d+', scan_data_file)
            cwe_num = match.group(0)[3:].lstrip('0')

            # get true or false
            if '\\T\\' in scan_data_file:
                true_false = 'TRUE'
            elif '\\F\\' in scan_data_file:
                true_false = 'FALSE'
            else:
                true_false = 'N/A'

            # get test case type
            if 'juliet' in scan_data_file:
                tc_type = 'juliet'
            elif 'kdm' in scan_data_file:
                tc_type = 'kdm'
            else:
                tc_type = 'N/A'

            # get test case language
            tc_lang = scan_data_file.rsplit('.', 4)[1].rsplit('_', 1)[1]

            # create xml name from scan data file name
            base_name = os.path.basename(scan_data_file)
            suffix = '_' + true_false[:1] + '_' + tc_type
            new_xml_name = str(base_name.rsplit('.', 2)[1]) + suffix + '.xml'

            self.copy_xml_file(scan_data_file, new_xml_name)

            cwe_id_padded = 'CWE' + cwe_num.zfill(3)

            self.xml_projects.append(
                Xml(cwe_id_padded, cwe_num, tc_type, true_false, tc_lang, new_xml_name, scan_data_file))

        return self.xml_projects

    def get_test_case_path(self, xml_projects):

        for i, xml_project in enumerate(xml_projects):

            true_false = getattr(self.xml_projects[i], 'true_false')[:1]
            xml_type = getattr(self.xml_projects[i], 'tc_type')
            xml_name = getattr(self.xml_projects[i], 'new_xml_name')[:-4]
            # todo: speed this up more by adding cwe

            key_list = xml_name.split('_')

            path = os.path.join(os.getcwd(), xml_type, true_false)

            for root, dirs, files in os.walk(path):

                # if all(x in root for x in key_list):
                if all(x in root for x in key_list):
                    print('ROOT----------', root)
                    setattr(self.xml_projects[i], 'tc_path', root.replace(os.getcwd(), ''))
                    break


                    # print('attrib-----------' ,xml_name)



        '''
        for i, scan_data_file in enumerate(scan_data_files):



            path1 = os.path.join(os.getcwd(), getattr(self.xml_projects[i], 'tc_type'))
            path1 = os.path.join(scan_data_file, getattr(self.xml_projects[i], 'true_false')[:1])
            test = scan_data_file.rsplit('.',2)[1]
            print('test-----------', test)
        '''

    #         print(path_part_2)
    #
    #         #for root, dirs, files in os.walk('c:\\01\\juliet'):
    #
    #         #   for file in files:
    #
    #
    #
    #
    #
    #         # self.xml_projects[i].__setattr__('juliet_tc_path', 'hello') #todo: keep for now, this shows that i can create an attrib
    #         # self.xml_projects[i].__setattr__('tc_path', 'hello') # todo: this works too
    #
    #
    #         path1 = os.path.join(os.getcwd(), getattr(self.xml_projects[i], 'tc_type'))
    #         path1 = os.path.join(path, getattr(self.xml_projects[i], 'true_false')[:1])
    #         test = path.rsplit('.',2)[1]
    #
    #         # if all(x in path for x in key_list):
    #         # if all(x in 'c:\\01\\juliet' for x in key_list):
    #         #    print('FOUND CWE121------', path)
    #
    #
    #         # setattr(self.xml_projects[i], 'tc_path', path)
    #         # print(path)
