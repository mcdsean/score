import os, re, zipfile, operator

import py_common


FVDL_NAME = "audit.fvdl"


class Xml(object):
    def __init__(self, cwe_id_padded, cwe_num, tc_type, true_false, tc_lang, new_xml_name, scan_data_file):
        self.cwe_id_padded = cwe_id_padded
        self.cwe_num = cwe_num
        self.tc_type = tc_type
        self.true_false = true_false
        self.tc_lang = tc_lang
        self.new_xml_name = new_xml_name
        self.scan_data_file = scan_data_file
        # runtime attributes
        self.tc_count = ''  # tc_count
        self.num_of_hits = ''  # num_of_hits
        self.percent_hits = ''  # percent_hits
        self.tc_path = ''  # tc_path

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
        # list of tc paths
        self.tc_paths = []

        # create or clean xml dir
        self.create_xml_dir()
        # get the xml info and create copies
        self.get_xml_info(self.scan_data_files)
        self.get_test_case_paths(self.scan_data_files)
        self.count_test_cases(self.xml_projects)
        self.sort_by_columns()

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
            tc_lang = scan_data_file.rsplit('.', 4)[1].rsplit('_', 1)[1].lower()

            # create xml name from scan data file name
            base_name = os.path.basename(scan_data_file)
            suffix = '_' + true_false[:1] + '_' + tc_type
            new_xml_name = str(base_name.rsplit('.', 2)[1]) + suffix + '.xml'

            self.copy_xml_file(scan_data_file, new_xml_name)

            cwe_id_padded = 'CWE' + cwe_num.zfill(3)

            self.xml_projects.append(
                Xml(cwe_id_padded, cwe_num, tc_type, true_false, tc_lang, new_xml_name, scan_data_file))

        return self.xml_projects


    def get_test_case_paths(self, xml_projects):

        key_list = []
        root_list = []

        tc_types = ['juliet', 'kdm']

        # get the lowest level, non-empty, paths for juliet and kdm
        for tc_type in tc_types:
            for root, dirs, files in os.walk(os.path.join(os.getcwd(), tc_type)):
                if files and not dirs:
                    root_list.append(root)

        for i, xml_project in enumerate(xml_projects):
            del key_list[:]

            # get the xml name for each project and use it's contents to grab the tc dir
            xml_name = getattr(self.xml_projects[i], 'new_xml_name')[:-4]

            key_list = xml_name.split('_')
            key_list[0] = key_list[
                              0] + '_'  # guard against confusion 'CWE78_' and 'CWE789_' #todo: this causes it to run a real long time but is probably not the real cause

            for root in root_list:
                if all(x in root for x in key_list):
                    print('ROOT FOUND----------', root)
                    setattr(self.xml_projects[i], 'tc_path', root.replace(os.getcwd(), '')[1:])
                    # root_list.remove(root)
                    break


    def count_test_cases(self, xml_projects):

        test_case_files = []

        for i, xml_project in enumerate(xml_projects):
            tc_type = getattr(self.xml_projects[i], 'tc_type')
            tc_lang = getattr(self.xml_projects[i], 'tc_lang')
            tc_path = os.path.join(os.getcwd(), getattr(self.xml_projects[i], 'tc_path'))

            if tc_type == 'juliet':
                del test_case_files[:]

                for root, dirs, files in os.walk(tc_path):
                    for file in files:
                        if file.endswith(tc_lang):
                            print('TEST CASE FILE', file)

                            # reduce filename to test case name by removing variant and file extension
                            file = re.sub('[a-z]?\.\w+$', '', file)
                            test_case_files.append(file)

                tc_count = len(set(test_case_files))
                setattr(self.xml_projects[i], 'tc_count', tc_count)

    def sort_by_columns(self):

        # reverse the order of the desired sort priority #todo: consider moving this to another location
        self.xml_projects.sort(key=operator.attrgetter('true_false'), reverse=False)
        self.xml_projects.sort(key=operator.attrgetter('tc_type'))
        self.xml_projects.sort(key=operator.attrgetter('cwe_id_padded'))
