import os, re, zipfile, operator

import py_common

FVDL_NAME = "audit.fvdl"


class TestCase(object):
    def __init__(self, cwe):
        self.tc_cwe = cwe

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
        self.tc_count = ''
        self.num_of_hits = ''
        self.percent_hits = ''
        self.tc_path = ''

        self.acceptable_weakness_ids = []
        self.used_wids = []

        self.files_that_hit = []

        print('PROJECT FILE---', self.scan_data_file)

    def test(self, u_wids):
        self.used_wids = u_wids

class Suite(object):
    def __init__(self, source_path, dest_path, tool_name):
        self.source_path = source_path
        self.dest_path = dest_path
        self.tool_name = tool_name

        # raw files produced by scanner
        self.scan_data_files = []
        # list of xml project objects
        self.xml_projects = []
        # list of tc paths
        self.tc_paths = []

        # runtime attributes
        self.name_space = ''

        self.tag_info = []
        self.acceptable_weakness_ids_full_list = []
        self.used_wids_per_cwe = []

        # auto-run methods on creation
        self.create_xml_dir()
        # get the xml info and create copies
        self.get_xml_info(self.scan_data_files)
        # get the test case counts
        self.get_test_case_paths_and_counts(self.scan_data_files)
        # import the weakness ids from vendor input sheet
        # self.import_weakness_ids(self.scan_data_files)
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

    def get_xml_info(self, scan_data_files):

        for scan_data_file in scan_data_files:

            # get cwe number from project name
            match = re.search('CWE\d+', scan_data_file)
            cwe_num = match.group(0)[3:].lstrip('0')

            # get test case language
            tc_lang = scan_data_file.rsplit('.', 4)[1].rsplit('_', 1)[1].lower()

            # get true or false
            if '\\T\\' in scan_data_file:
                true_false = 'TRUE'
            elif '\\F\\' in scan_data_file:
                true_false = 'FALSE'
            else:
                true_false = 'N/A'

            # create xml name from scan data file name
            base_name = os.path.basename(scan_data_file)

            # get test case type
            if 'juliet' in scan_data_file:
                tc_type = 'juliet'
                # suffix = '_' + true_false[:1] + '_' + 'juliet'
                new_xml_name = str(base_name.rsplit('.', 2)[1]) + '_' + true_false[:1] + '_' + 'juliet' + '.xml'
            elif 'kdm' in scan_data_file:
                tc_type = 'kdm'
                new_xml_name = re.sub('(_[TF]_)', '_', str(base_name.rsplit('.', 2)[1])) + '_' + true_false[
                                                                                                 :1] + '_' + 'kdm' + '.xml'
            else:
                tc_type = 'N/A'
                new_xml_name = 'N/A'

            self.copy_xml_file(scan_data_file, new_xml_name)

            cwe_id_padded = 'CWE' + cwe_num.zfill(3)

            self.xml_projects.append(
                Xml(cwe_id_padded, cwe_num, tc_type, true_false, tc_lang, new_xml_name, scan_data_file))

        return self.xml_projects

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

    def get_test_case_paths_and_counts(self, scan_data_files):

        key_list = []
        root_list = []

        tc_types = ['juliet', 'kdm']

        # get the lowest level, non-empty, paths for juliet and kdm
        for tc_type in tc_types:
            for root, dirs, files in os.walk(os.path.join(os.getcwd(), tc_type)):
                if files and not dirs:
                    root_list.append(root)

        for i, xml_project in enumerate(scan_data_files):
            del key_list[:]

            # get the xml name for each project and use it's contents to grab the tc dir
            xml_name = getattr(self.xml_projects[i], 'new_xml_name')[:-4]

            key_list = xml_name.split('_')
            if 'kdm' in xml_name and 'CWE123' in key_list[0]:
                key_list[0] = 'CWE123a'  # account for kdm 123a naming anomaly
            key_list[0] = key_list[0] + '_'  # guard against confusion 'CWE78_' and 'CWE789_'

            for root in root_list:
                if all(x in root for x in key_list):
                    print('TC PATH FOUND----------', root)
                    tc_path = root.replace(os.getcwd(), '')[1:]
                    setattr(self.xml_projects[i], 'tc_path', tc_path)
                    project_id = i
                    self.count_test_cases(project_id, tc_path)
                    # root_list.remove(root) #todo: this was intended to speed up searches but left some fields blank in the spreadsheet (delete or troubleshoot)
                    break

    def count_test_cases(self, projedt_id, tc_path):
        test_case_files = []

        tc_type = getattr(self.xml_projects[projedt_id], 'tc_type')
        tc_lang = getattr(self.xml_projects[projedt_id], 'tc_lang')
        for root, dirs, files in os.walk(tc_path):

            for file in files:
                if file.endswith(tc_lang):
                    if tc_type == 'juliet':
                        # reduce filename to test case name by removing variant and file extension
                        file = re.sub('[a-z]?\.\w+$', '', file)
                        test_case_files.append(file)
                        #print('JULIET TEST CASE FILE', file)
                    elif tc_type == 'kdm':
                        if not file.endswith(".h") and not file.endswith("_a.c") and not file.endswith(
                                ".obj") and file.startswith("SFP"):
                            test_case_files.append(file)
                            #print('KDM TEST CASE FILE', file)
                    else:
                        print('Not a KDM or Juliet Test Case File.')

        tc_count = len(set(test_case_files))
        setattr(self.xml_projects[projedt_id], 'tc_count', tc_count)

    # def import_weakness_ids(self, scan_data_files):
    #     cwe_weakness_ids = []
    #
    #     ws = wb['Weakness IDs']
    #
    #     # get weakness ids from duplicated vendor sheet
    #     for row_idx in ws.iter_rows():
    #         for cell in row_idx:
    #             if str(cell.value) == cwe.lstrip('0'):
    #                 for cell in row_idx:
    #                     cwe_weakness_ids.append(cell.value)
    #
    #                 return cwe_weakness_ids


    def sort_by_columns(self):

        # reverse the order of the desired sort priority #todo: consider moving this to another location
        self.xml_projects.sort(key=operator.attrgetter('true_false'), reverse=False)
        self.xml_projects.sort(key=operator.attrgetter('tc_type'))
        self.xml_projects.sort(key=operator.attrgetter('cwe_id_padded'))

