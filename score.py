#
#
# Running this script will automatically score the KDM and Juliet test case suites
#
# 2016-12-01 smcdonagh@keywcorp.com: initial version
#
import os, re, argparse, shutil, py_common, operator
import xml.etree.ElementTree as ET
import zipfile

from suite import Suite, TestCase

from time import strftime

from openpyxl import load_workbook
from openpyxl.styles import Border, Side, PatternFill, Font, Alignment
from openpyxl.chart import BarChart, Reference
# from openpyxl.formatting.rule import ColorScaleRule

from openpyxl.formatting.rule import ColorScaleRule

from operator import itemgetter


# Global for command line argument
normalize_juliet_false_scoring = False

TOOL_NAME = 'fortify'
XML_OUTPUT_DIR = 'xmls'
WID_DELIMITER_FORTIFY = ':'

def format_workbook():
    hit_sheet_titles = ['File (Juliet/False)', 'Line #', 'Opp Block', 'Opportunities', ]

    '''
    ws1.protect()	
    ws2.protect()	
    ws3.protect()	
    '''

    # todo: can do range for all here
    # set varying col widths for sheet 1
    ws1.column_dimensions['A'].width = 8
    ws1.column_dimensions['B'].width = 8
    ws1.column_dimensions['C'].width = 8
    ws1.column_dimensions['D'].width = 8
    ws1.column_dimensions['E'].width = 8
    ws1.column_dimensions['F'].width = 8
    ws1.column_dimensions['G'].width = 8
    ws1.sheet_view.zoomScale = 90

    # set varying col widths for sheet 2
    ws2.column_dimensions['A'].width = 8
    ws2.column_dimensions['B'].width = 6
    ws2.column_dimensions['C'].width = 6
    ws2.column_dimensions['D'].width = 5
    ws2.column_dimensions['E'].width = 6
    ws2.column_dimensions['F'].width = 5
    ws2.column_dimensions['G'].width = 43
    ws2.column_dimensions['H'].width = 62
    ws2.column_dimensions['I'].width = 105
    ws2.sheet_view.zoomScale = 85

    # hit data
    ws3.column_dimensions['A'].width = 146
    ws3.column_dimensions['B'].width = 6
    ws3.column_dimensions['C'].width = 86
    ws3.column_dimensions['D'].width = 11
    ws3.sheet_view.zoomScale = 70
    ws3.cell(row=1, column=1).alignment = Alignment(horizontal="center")
    # freeze first row and column
    ws3.freeze_panes = ws3['A2']
    ws3.sheet_properties.tabColor = "A9D08E"
    # write column headers
    for idx, title in enumerate(hit_sheet_titles):
        set_appearance(ws3, 1, idx + 1, 'fg_fill', 'A9D08E')
        ws3.cell(row=1, column=idx + 1).value = title
        ws3.cell(row=1, column=idx + 1).alignment = Alignment(horizontal="center")



def count_kdm_test_cases(fpr_name):
    full_path = ""
    beginning_of_path = ""
    end_of_path = ""
    found = False
    test_cases_files = []  # reserved for alt counting approach
    path_and_count = []
    t_f = ""

    if "\\T\\" in fpr_name:
        t_f = "T"
    else:
        t_f = "F"

    beginning_of_path = fpr_name.rsplit("\\", 4)[0]
    beginning_of_path = beginning_of_path + "\\kdm\\" + t_f

    dir_info = fpr_name.rsplit(".", 2)[1]
    cwe_ = dir_info.split("_")[0] + "_"

    if "123" in cwe_:
        cwe_ = "123a_"

    bin = fpr_name.rsplit("_", 1)[1][:-4]
    depth = "Depth_" + fpr_name.rsplit("_", 2)[1]

    complexity = fpr_name.rsplit("_", 4)[1]

    end_of_path = "Language_C\\" + complexity + "\\" + depth + "\\" + bin

    # for root,dirs,files in os.walk(path):
    for root, dirs, files in os.walk(beginning_of_path):

        for dir in dirs:

            if cwe_ in dir:

                full_path = beginning_of_path + "\\" + dir + "\\" + end_of_path

                for path, dirs, files in os.walk(full_path):

                    for file in files:

                        if not file.endswith(".h") and not file.endswith("_a.c") and not file.endswith(
                                ".obj") and file.startswith("SFP"):
                            full_path_and_filename = os.path.join(full_path, file)
                            test_cases_files.append(full_path_and_filename)
                found = True

        if found:
            break

    # get the total unique hits per test case
    score = len(set(test_cases_files))

    path_and_count.extend([score, full_path])

    return path_and_count


def count_juliet_test_cases(fpr_name):
    count = 0
    full_path = ""
    found = False
    test_cases = []
    path_and_count = []
    juliet_tc_path = ""
    t_f = ""

    # get juliet regex
    regex = py_common.get_primary_testcase_filename_regex()

    if "\\T\\" in fpr_name:
        t_f = "T"
    else:
        t_f = "F"

    juliet_tc_path = fpr_name.rsplit("\\", 4)[0]
    juliet_tc_path = juliet_tc_path + "\\juliet\\" + t_f

    dir_info = fpr_name.rsplit(".", 2)[1]
    cwe_ = dir_info.split("_")[0] + "_"

    if "_" in dir_info:
        sub_dir = dir_info.split("_")[1]
    else:
        sub_dir = "none"

    for root, dirs, files in os.walk(juliet_tc_path):

        for dir in dirs:

            full_path = root + "\\" + dir

            if sub_dir != "none":
                if (cwe_ in full_path) and (sub_dir in full_path):
                    test_cases = py_common.find_files_in_dir(full_path, regex)
                    found = True
                    break

            else:
                if (cwe_ in full_path):
                    test_cases = py_common.find_files_in_dir(full_path, regex)
                    found = True
                    break

        if found:
            break

    # count juliet test cases for this project
    for test_case in test_cases:
        count += 1

    path_and_count.extend([count, full_path])

    return path_and_count


def count_juliet_test_cases_OROGINAL(fpr_name):
    count = 0
    full_path = ""
    found = False
    test_cases = []
    path_and_count = []
    juliet_tc_path = ""
    t_f = ""

    # get juliet regex
    regex = py_common.get_primary_testcase_filename_regex()

    if "\\T\\" in fpr_name:
        t_f = "T"
    else:
        t_f = "F"

    juliet_tc_path = fpr_name.rsplit("\\", 4)[0]
    juliet_tc_path = juliet_tc_path + "\\juliet\\" + t_f

    dir_info = fpr_name.rsplit(".", 2)[1]
    cwe_ = dir_info.split("_")[0] + "_"

    if "_" in dir_info:
        sub_dir = dir_info.split("_")[1]
    else:
        sub_dir = "none"

    for root, dirs, files in os.walk(juliet_tc_path):

        for dir in dirs:

            full_path = root + "\\" + dir

            if sub_dir != "none":
                if (cwe_ in full_path) and (sub_dir in full_path):
                    test_cases = py_common.find_files_in_dir(full_path, regex)
                    found = True
                    break

            else:
                if (cwe_ in full_path):
                    test_cases = py_common.find_files_in_dir(full_path, regex)
                    found = True
                    break

        if found:
            break

    # count juliet test cases for this project
    for test_case in test_cases:
        count += 1

    path_and_count.extend([count, full_path])

    return path_and_count


def extract_fvdl_from_fpr(fpr_file, output_dir):
    # fortify .fpr files need unzipped to get the xml
    myzip = zipfile.ZipFile(fpr_file, mode='r')
    myzip.extract(FVDL_NAME, path=output_dir)
    myzip.close()


def create_or_clean_xml_dir(xml_dir):
    # create, or empty, 'xmls' folder
    #
    # Note: Deleting entire folder and then re-creating it immediately sometimes conflicts
    # with anti-virus sortware and cannot always release handles quick enough, so the entire
    # parent folder is not deleted, only the files withing it. This prevents this problem
    #
    if not os.path.exists(xml_dir):
        py_common.print_with_timestamp("The path \"" + xml_dir + "\" does not exist")
        py_common.print_with_timestamp("creating directory \"" + xml_dir + "\"")
        os.makedirs(xml_dir)
    else:
        py_common.print_with_timestamp(xml_dir + " already exists. Cleaning before use...")
        fileList = os.listdir(xml_dir)
        for fileName in fileList:
            os.remove(xml_dir + "//" + fileName)


def paint_sheet(used_wid_list):
    for wid in used_wid_list:
        ws = wb['Weakness IDs']
        set_appearance(ws, 3, 3, 'fg_fill', 'F4B084')


def get_data(src_path, dest_path):
    # container to hold one slot of data per scan
    data_list = []
    juliet_f_hits_total = []

    used_weakness_ids_total = []
    used_unique_ids = []

    # kdm_counts_and_path = []
    # juliet_counts_and_path = []

    create_or_clean_xml_dir(dest_path)

    # fortify files are not in standard xml format
    if TOOL_NAME == 'fortify':
        scan_data_files = py_common.find_files_in_dir(src_path, '.*?\.fpr$')
    else:
        scan_data_files = py_common.find_files_in_dir(src_path, '.*?\.xml$')

    for scan_data_file in scan_data_files:

        # get t/f from scan data file name #todo: put in function named get test_case_type_and_polarity()
        if '\\T\\' in scan_data_file:
            t_f = 'TRUE'
        else:
            t_f = 'FALSE'

        proj_name = os.path.basename(scan_data_file)
        proj_sub_name = proj_name.rsplit('.', 2)[1]

        if 'juliet' in scan_data_file:
            test_case_type = 'juliet'
            xml_name = proj_sub_name + '_' + t_f[:1] + '_' + test_case_type + '.xml'
        elif 'kdm' in scan_data_file:
            test_case_type = 'kdm'
            xml_name = proj_sub_name + '_' + test_case_type + '.xml'
        else:
            print('NO TEST CASE TYPE FOUND!')

        if TOOL_NAME == 'fortify':
            extract_fvdl_from_fpr(scan_data_file, dest_path)

        # format xml name
        tool_path_to_xml = os.path.join(dest_path, FVDL_NAME)
        new_path_to_xml = os.path.join(dest_path, xml_name)
        # create fresh xml name
        os.rename(tool_path_to_xml, new_path_to_xml)

        # get cwe number from project name
        match = re.search('CWE\d+', proj_name)
        cwe_num = match.group(0)[3:].lstrip('0')
        cwe_padded = 'CWE' + cwe_num.zfill(3)

        # --- AUTO SCORE --- returns the score, used weakness ids, and opp counts for the current project
        score, used_weakness_ids, juliet_f_hits, juliet_f_testcase_path = auto_score(new_path_to_xml, cwe_num,
                                                                                     test_case_type, t_f)
        used_weakness_ids_total += used_weakness_ids
        juliet_f_hits_total += juliet_f_hits
        used_unique_ids = remove_dups(used_weakness_ids_total)

        # juliet
        if test_case_type == 'juliet':
            juliet_counts_and_path = count_juliet_test_cases(scan_data_file)

            # for juliet false test cases, use opps vs test case count
            if t_f == 'TRUE':
                juliet_count = juliet_counts_and_path[0]
            elif t_f == 'FALSE':
                # juliet_test_case_path = os.path.join(os.getcwd(), 'juliet', os.path.dirname(juliet_f_testcase_path))
                # opps_per_test_case = get_opp_counts_per_test_case(juliet_test_case_path)
                opps_per_test_case = get_opp_counts_per_test_case(juliet_f_testcase_path)
                juliet_count = sum(opps_per_test_case.values())
            else:
                print('TRUE/FALSE NOT FOUND')

            juliet_path = juliet_counts_and_path[1]
            if juliet_count != 0:
                percent_hits = (score / juliet_count) * 100
            else:
                percent_hits = 0
            data_list.append(
                [cwe_padded, test_case_type, juliet_count, score, round(percent_hits, 1), xml_name, juliet_path, t_f,
                 proj_name])

        # kdm
        if test_case_type == 'kdm':
            kdm_counts_and_path = count_kdm_test_cases(scan_data_file)
            kdm_count = kdm_counts_and_path[0]
            kdm_path = kdm_counts_and_path[1]
            if kdm_count != 0:
                percent_hits = (score / kdm_count) * 100
            else:
                percent_hits = 0
            data_list.append(
                [cwe_padded, test_case_type, kdm_count, score, round(percent_hits, 1), xml_name, kdm_path, t_f,
                 proj_name])

    paint_sheet(used_unique_ids)

    write_opp_counts_to_sheet(juliet_f_hits_total)

    return data_list


def get_schemas(suite_dat):
    schemas = {}
    weakness_id_schemas = []

    tag_ids = getattr(suite_dat, 'tag_info')

    # get xml schemas from vendor input file
    for idx, content in enumerate(tag_ids):

        schema = 'ns1:' + getattr(suite_dat, 'tag_info')[idx][1].replace('/', '/ns1:')

        # finding type
        # todo: simplify these common components by adding function
        if content[0].lower() == 'finding_type':
            if content[2].lower() == 'tag':
                schemas['finding_type_schema'] = schema
            continue
        # file name
        if content[0].lower() == 'file_name':
            if content[2].lower() == 'tag':
                schemas['file_name_schema'] = schema
            elif content[2].lower() == 'attribute':
                schemas['file_name_schema'] = schema.rsplit('/', 1)[0]
                schemas['file_name_attrib'] = schema.rsplit(':', 1)[1]
            continue
        # line number
        if content[0].lower() == 'line_number':
            if content[2].lower() == 'tag':
                schemas['line_number_schema'] = schema
            elif content[2].lower() == 'attribute':
                schemas['line_number_schema'] = schema.rsplit('/', 1)[0]
                schemas['line_number_attrib'] = schema.rsplit(':', 1)[1]
            continue
        # function name
        if content[0].lower() == 'function_name':
            if content[2].lower() == 'tag':
                schemas['function_name_schema'] = schema
            elif content[2].lower() == 'attribute':
                schemas['function_name_schema'] = schema.rsplit('/', 1)[0]
                schemas['function_name_attrib'] = schema.rsplit(':', 1)[1]
            continue
        # weakness ids
        if 'weakness' in content[0].lower():
            weakness_id_schemas.append('ns1:' + str(tag_ids[idx][1]).replace('/', '/ns1:'))

    return schemas, weakness_id_schemas


def score_xmls_1(suite_dat):
    ns = {}
    wid_pieces_that_hit = []

    schemas, weakness_id_schemas = get_schemas(suite_dat)

    for xml_project in suite_data.xml_projects:

        used_wids = []
        test_cases = []
        test_case_files = []

        # read namespace from the first xml since it will be the same for all other xmls
        xml_path = os.path.join(os.getcwd(), 'xmls', getattr(xml_project, 'new_xml_name'))
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns["ns1"] = root.tag.split("}")[0].replace('{', '')

        setattr(suite_dat, 'name_space', ns)  # todo: we only need this one time

        print('XML', xml_path)

        # get the acceptable wids for this xml
        good_wids = getattr(xml_project, 'acceptable_weakness_ids')
        test_case_type = getattr(xml_project, 'tc_type')
        tool_name = getattr(suite_data, 'tool_name')

        # 1. parse thru each row in this xml looking for good wids, and get the filename & line #
        # for vuln in root.findall('./' + finding_type_schema, ns):
        for vuln in root.findall('./' + schemas['finding_type_schema'], ns):
            #todo: add condition for tag vs attribute; need flags in switch statement above
            del wid_pieces_that_hit[:]

            # 2. get relative path/filename and line number for this row in this xml
            file_path = vuln.find(schemas['file_name_schema'], ns).attrib[schemas['file_name_attrib']]
            line_number = vuln.find(schemas['line_number_schema'], ns).attrib[schemas['line_number_attrib']]
            filename = os.path.basename(file_path)
            function_name = vuln.find(schemas['function_name_schema'], ns).attrib[schemas['function_name_attrib']]

            # 3. get all pieces of the wid for this row in the xml
            for idx, weakness_id in enumerate(weakness_id_schemas):
                wid_piece = vuln.find(weakness_id_schemas[idx], ns)
                if wid_piece is not None:
                    wid_pieces_that_hit.append(wid_piece.text)

            # 4. look at each non-empty cell in the spreadsheet for acceptable wids
            for good_wid in good_wids:
                if tool_name == 'fortify':
                    good_wid_pieces = good_wid.split(WID_DELIMITER_FORTIFY)
                else:
                    good_wid_pieces = good_wid

                # 5. if the current cell in spreadsheet does not contain a cwe # or is blank, move on
                if good_wid != 'None' and not good_wid.isdigit():

                    # 6. see if ALL of the pieces for this row match this cell's good wid
                    if set(wid_pieces_that_hit) != set(good_wid_pieces):
                        continue

                    else:
                        # add the used wid to the list if it is not already there
                        if good_wid not in used_wids:
                            used_wids.append(good_wid)

                        test_case_files.append([filename, line_number])

                        # todo: consider using 'not in' like above, but may want to write all to sheet instead?
                        # juliet test case
                        if test_case_type == 'juliet':
                            test_case_name = re.sub('[a-z]?\.\w+$', '', filename)
                        # kdm test case
                        elif test_case_type == 'kdm':
                            test_case_name = re.sub('[_a]?\.\w+$', '', filename)
                        else:
                            test_case_name = ''
                        test_cases.append(test_case_name)

                    #############

                    # TODO: NEW CODE-------------------------------------------------------4/26/17
                    # get_opp_counts_per_test_case(os.path.join(os.getcwd(), 'juliet', os.path.dirname(file_path)))

                    # $$$$$$$$$$$$$$$$$$$$$$$
                    # get the test cases list that holds the objects
                    test_case_file = getattr(xml_project, 'test_cases')
                    # if the test case name does not exist yet, create a new 'TestCase' object
                    test_case_file.append(TestCase([file_path, int(line_number)]))
                    setattr(xml_project, 'test_cases', test_case_file)
                    #############

                # empty good wid cell so move on
                else:
                    continue

        score = len(set(test_cases))

        print('SCORE:', score)
        setattr(xml_project, 'num_of_hits', score)
        setattr(xml_project, 'used_wids', used_wids)
        setattr(xml_project, 'test_case_files_that_hit', file_path)
        setattr(xml_project, 'test_case_files_and_line_that_hit', test_case_files)


def score_xmls(suite_dat):
    ns = {}
    wid_pieces_that_hit = []
    row = 1

    schemas, weakness_id_schemas = get_schemas(suite_dat)

    for xml_project in suite_data.xml_projects:

        used_wids = []
        test_cases = []
        test_case_files = []
        file_paths = []

        # read namespace from the first xml since it will be the same for all other xmls
        xml_path = os.path.join(os.getcwd(), 'xmls', getattr(xml_project, 'new_xml_name'))
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ns["ns1"] = root.tag.split("}")[0].replace('{', '')

        setattr(suite_dat, 'name_space', ns)  # todo: we only need this one time

        print('XML', xml_path)

        # get the acceptable wids for this xml
        good_wids = getattr(xml_project, 'acceptable_weakness_ids')
        test_case_type = getattr(xml_project, 'tc_type')
        tool_name = getattr(suite_data, 'tool_name')

        # 1. parse thru each row in this xml looking for good wids, and get the filename & line #
        # for vuln in root.findall('./' + finding_type_schema, ns):
        for vuln in root.findall('./' + schemas['finding_type_schema'], ns):

            # todo: add condition for tag vs attribute; need flags in switch statement above
            del wid_pieces_that_hit[:]

            # 2. get relative path/filename and line number for this row in this xml
            file_path = vuln.find(schemas['file_name_schema'], ns).attrib[schemas['file_name_attrib']]
            line_number = vuln.find(schemas['line_number_schema'], ns).attrib[schemas['line_number_attrib']]
            function_name = vuln.find(schemas['function_name_schema'], ns).attrib[schemas['function_name_attrib']]

            # 3. get all pieces of the wid for this row in the xml
            for idx, weakness_id in enumerate(weakness_id_schemas):
                wid_piece = vuln.find(weakness_id_schemas[idx], ns)
                if wid_piece is not None:
                    wid_pieces_that_hit.append(wid_piece.text)

            # 4. look at each non-empty cell in the spreadsheet for acceptable wids
            for good_wid in good_wids:
                if tool_name == 'fortify':
                    good_wid_pieces = good_wid.split(WID_DELIMITER_FORTIFY)
                else:
                    good_wid_pieces = good_wid

                # 5. if the current cell in spreadsheet does not contain a cwe # or is blank, move on
                if good_wid != 'None' and not good_wid.isdigit():

                    # 6. see if ALL of the pieces for this row match this cell's good wid
                    if set(wid_pieces_that_hit) != set(good_wid_pieces):
                        continue

                    else:
                        # this is a good wid so add it to the list if it is not already there
                        if good_wid not in used_wids:
                            used_wids.append(good_wid)

                        test_case_files.append([file_path, int(line_number)])

                        if test_case_type == 'juliet':
                            test_case_name = re.sub('[a-z]?\.\w+$', '', file_path)
                        elif test_case_type == 'kdm':
                            test_case_name = re.sub('[_a]?\.\w+$', '', file_path)
                        else:
                            test_case_name = ''
                        test_cases.append(test_case_name)
                        file_paths.append(file_path)

                        #############++++++++++++++++++++++++++++++++
                        # todo: get_opp_counts_per_test_case(os.path.join(os.getcwd(), 'juliet', os.path.dirname(file_path)))

                        # ws3.cell(row=row + 1, column=1).value = file_path
                        # ws3.cell(row=row + 1, column=2).value = line_number
                        # row += 1

                        # &&&&&&&&&&&&&&&&&&&&&&
                        # temp = file_path.rsplit('/', 1)[0]
                        # get_opp_counts_per_file(os.path.join(os.getcwd(), 'juliet', temp))

                        # &&&&&&&&&&&&&&&&&&&&&&

                        # get the test cases list that holds the objects
                        test_case_objects = getattr(xml_project, 'test_cases')

                        # if this is a new test case name, create a new object for it
                        if test_case_name not in test_case_objects:
                            # create a new test case object
                            test_case_objects.append(TestCase(test_case_name))
                            # add the new test case object to the xml project list
                            setattr(xml_project, 'test_cases', test_case_objects)
                            test_case_objects[0].hit_data.append([file_path, line_number, function_name])

                        # the test case object now exists so find the correct name and update its hit list
                        else:
                            for test_case_object in test_case_objects:
                                if test_case_object.test_case_name == test_case_name:
                                    # test_case_object.function_name = function_name
                                    # setattr(test_case_object, 'enclosing_function_name', function_name)
                                    hit_data = getattr(test_case_object, 'hit_data')
                                    hit_data.append([file_path, line_number, function_name])

                                    #############++++++++++++++++++++++++++++++++

                # empty acceptable wid cell on spreadsheet so move on #todo: possibly break or continue to speed up?
                else:
                    continue

        score = len(set(test_cases))

        print('SCORE:', score)
        setattr(xml_project, 'num_of_hits', score)
        setattr(xml_project, 'used_wids', used_wids)
        setattr(xml_project, 'test_case_files_that_hit', file_paths)


def collect_hit_data(suite_dat):
    # file name, line number, and enclosing function of all hits
    hit_data = []

    # all test case files names, and line, from each test cases object
    for xml_project in suite_dat.xml_projects:
        test_case_objects = xml_project.test_cases
        for test_case_obj in test_case_objects:
            hit_data += test_case_obj.hit_data

    # sort the hits by file name and then line number
    hit_data = sorted(hit_data, key=operator.itemgetter(0, 1))

    write_hit_data(hit_data)


def write_hit_data(hit_data):
    row = 1

    file_name_dups = []
    file_seen = set()
    previous_file_name_and_line = []

    for hit in hit_data:

        # write the file name and line for each hit
        ws3.cell(row=row + 1, column=1).value = hit[0]  # file name
        ws3.cell(row=row + 1, column=2).value = hit[1]  # line number
        ws3.cell(row=row + 1, column=3).value = hit[2]  # function name
        # set appearance and alignment
        # todo: consider doing this all at once at the end to speed up?
        # todo: put this in a loop to cover all columns which is not determined yet
        set_appearance(ws3, row + 1, 1, 'fg_fill', 'FFFFFF')
        set_appearance(ws3, row + 1, 2, 'fg_fill', 'FFFFFF')
        set_appearance(ws3, row + 1, 3, 'fg_fill', 'FFFFFF')
        ws3.cell(row=row + 1, column=2).alignment = Alignment(horizontal="right")
        ws3.cell(row=row + 1, column=3).alignment = Alignment(horizontal="right")

        # todo: move this to score_xmls...THIS WORKS
        # identify the duplicate files only
        if hit[0] in file_seen:
            file_name_dups.append(hit[0])
            ws3.cell(row=row, column=4).value = hit[0]  # todo: DEBUG code, delete when thru
        else:
            file_seen.add(hit[0])

        row += 1

    row = 1
    # todo: create new function here
    # for each file name check the duplicate list and highlight it if it is a duplicate


    for hit in hit_data:

        for dup_file_name in file_name_dups:

            # if file name is a duplicate, highlight it's row
            if hit[0] == dup_file_name:

                temp = list(hit[:2])
                if previous_file_name_and_line == list(hit[:2]):
                    # todo: put in loop to cove all cols
                    # todo: write this info to the test case object
                    #  gray - file name an line combo are not unique if
                    #  previous sorted value is identical to this sample
                    set_appearance(ws3, row + 1, 1, 'fg_fill', 'D9D9D9')
                    set_appearance(ws3, row + 1, 2, 'fg_fill', 'D9D9D9')
                    set_appearance(ws3, row + 1, 3, 'fg_fill', 'D9D9D9')
                    # adjust previous row
                    set_appearance(ws3, row, 1, 'fg_fill', 'D9D9D9')
                    set_appearance(ws3, row, 2, 'fg_fill', 'D9D9D9')
                    set_appearance(ws3, row, 3, 'fg_fill', 'D9D9D9')

                else:
                    # red - unique file name and line number
                    set_appearance(ws3, row + 1, 1, 'fg_fill', 'FFC7CE')
                    set_appearance(ws3, row + 1, 2, 'fg_fill', 'FFC7CE')
                    set_appearance(ws3, row + 1, 3, 'fg_fill', 'FFC7CE')
                previous_file_name_and_line = list(hit[:2])

        row += 1


def write_opp_counts_2(suite_dat):

    ##############################################################################################################
    opportunity_count_sheet_titles = ['File (Juliet/False)', 'Line #', 'Hits(Scored)', 'Opportunities', ]
    ##############################################################################################################

    row = 1
    file_names_and_line_numbs = []

    # freeze first row and column
    ws3.freeze_panes = ws3['A2']
    ws3.sheet_properties.tabColor = "A9D08E"

    # write column headers
    for idx, title in enumerate(opportunity_count_sheet_titles):
        set_appearance(ws3, row, idx + 1, 'fg_fill', 'A9D08E')
        ws3.cell(row=1, column=idx + 1).value = title
        ws3.cell(row=1, column=idx + 1).alignment = Alignment(horizontal="center")

    # all test case files names, and line, from each test cases object
    for xml_project in suite_dat.xml_projects:
        # file_names_and_line_numbs.append(xml_project.test_case_files_and_line_that_hit)
        file_names_and_line_numbs += xml_project.test_case_files_and_line_that_hit

        test_case_objects = xml_project.test_cases


        for test_case_obj in test_case_objects:
            row += 1
            # ws3.cell(row=row, column=3).value = test_case_obj.enclosing_function_name
            ws3.cell(row=row, column=3).value = getattr(test_case_obj, 'enclosing_function_name')

    '''
    # all test case files names, and line, from each test cases object
    for xml_project in suite_dat.xml_projects:
        test_case_objects = xml_project.test_cases
        for test_case_obj in test_case_objects:
            file_names_and_line_numbs.append(test_case_obj.test_case_name)
    '''

    # sort the list by file name and then line number
    file_names_and_line_numbs = sorted(file_names_and_line_numbs, key=operator.itemgetter(0, 1))

    # todo: put this and associated code into test case object 'duplicate_file_names' in score_xmls
    file_name_dups = []
    file_seen = set()
    previous_file_name_and_line = []
    row = 1
    for file_name_and_line in file_names_and_line_numbs:

        # write the file name and line for each hit
        ws3.cell(row=row + 1, column=1).value = file_name_and_line[0]
        ws3.cell(row=row + 1, column=2).value = file_name_and_line[1]
        # set appearance and alignment
        # todo: put this in a loop to cover all columns which is not determined yet
        set_appearance(ws3, row + 1, 1, 'fg_fill', 'FFFFFF')
        set_appearance(ws3, row + 1, 2, 'fg_fill', 'FFFFFF')
        ws3.cell(row=row + 1, column=2).alignment = Alignment(horizontal="right")

        # todo: move this to score_xmls...THIS WORKS
        # identify the duplicate files only
        if file_name_and_line[0] in file_seen:
            file_name_dups.append(file_name_and_line[0])
            #ws3.cell(row=row, column=3).value = file_name_and_line[0]  # todo: DEBUG code, delete when thru
        else:
            file_seen.add(file_name_and_line[0])

        row += 1

    row = 1
    # todo: create new function here
    # for each file name check the duplicate list and highlight it if it is a duplicate
    for file_name_and_line in file_names_and_line_numbs:

        for dup_file_name in file_name_dups:

            # if file name is a duplicate, highlight it's row
            if file_name_and_line[0] == dup_file_name:

                if previous_file_name_and_line == file_name_and_line:
                    # todo: put in loop to cove all cols
                    # todo: write this info to the test case object
                    #  gray - file name an line combo are not unique if
                    #  previous sorted value is identical to this sample
                    set_appearance(ws3, row + 1, 1, 'fg_fill', 'D9D9D9')
                    set_appearance(ws3, row + 1, 2, 'fg_fill', 'D9D9D9')
                    # adjust previous row
                    set_appearance(ws3, row, 1, 'fg_fill', 'D9D9D9')
                    set_appearance(ws3, row, 2, 'fg_fill', 'D9D9D9')

                else:
                    # red - unique file name and line number
                    set_appearance(ws3, row + 1, 1, 'fg_fill', 'FFC7CE')
                    set_appearance(ws3, row + 1, 2, 'fg_fill', 'FFC7CE')
                previous_file_name_and_line = file_name_and_line

        row += 1


def write_opp_counts_1(suite_dat):
    ##############################################################################################################
    opportunity_count_sheet_titles = ['File (Juliet/False)', 'Line #', 'Hits(Scored)', 'Opportunities', ]
    ##############################################################################################################

    row = 1
    file_names_and_line_numbs = []

    # freeze first row and column
    ws3.freeze_panes = ws3['A2']
    ws3.sheet_properties.tabColor = "A9D08E"

    # write column headers
    for idx, title in enumerate(opportunity_count_sheet_titles):
        set_appearance(ws3, row, idx + 1, 'fg_fill', 'A9D08E')
        ws3.cell(row=1, column=idx + 1).value = title
        ws3.cell(row=1, column=idx + 1).alignment = Alignment(horizontal="center")

    # all tese cases files names, and line, from each test cases object
    for xml_project in suite_dat.xml_projects:
        test_case_objects = xml_project.test_cases
        for test_case_obj in test_case_objects:
            file_names_and_line_numbs.append(test_case_obj.tc_file_name)

    # sort the list by file name and then line number
    file_names_and_line_numbs = sorted(file_names_and_line_numbs, key=operator.itemgetter(0, 1))

    # todo: put this and associated ocde into test case object 'duplicate_file_names' in score_xmls
    file_name_dups = []
    file_seen = set()
    previous_file_and_line = []


    for file_name_and_numb in file_names_and_line_numbs:

        ws3.cell(row=row + 1, column=1).value = file_name_and_numb[0]
        ws3.cell(row=row + 1, column=2).value = file_name_and_numb[1]
        # set appearance and alignment
        # todo: put this in a loop to cover all columns which is not determined yet
        set_appearance(ws3, row + 1, 1, 'fg_fill', 'FFFFFF')
        set_appearance(ws3, row + 1, 2, 'fg_fill', 'FFFFFF')
        ws3.cell(row=row + 1, column=2).alignment = Alignment(horizontal="right")

        # todo: move this to score_xmls...THIS WORKS
        # identify the duplicate files only
        if file_name_and_numb[0] in file_seen:
            file_name_dups.append(file_name_and_numb[0])
            ws3.cell(row=row, column=3).value = file_name_and_numb[0]  # todo: DEBUG code, delete when thru
        else:
            file_seen.add(file_name_and_numb[0])

        # # todo: move this to score_xmls...EXPERIMENTAL
        # # identify the duplicate files only
        # if file_name_and_numb in file_seen:
        #     file_dups.append(file_name_and_numb)
        #     ws3.cell(row=row, column=3).value = file_name_and_numb[0]  # todo: DEBUG code, delete when thru
        # else:
        #     file_seen.append(file_name_and_numb)

        row += 1

    # deduped based on both file name and line
    deduped_list = set(tuple(element) for element in file_names_and_line_numbs)
    # NOTE: to convert set() back to list, use: [list(t) for t in set(tuple(element) for element in xx)]

    row = 1
    # todo: consider de-duplicating all files with matching line numbers
    # for each file check the duplicate list and highlight it if it is a duplicate
    for file_name_and_numb in file_names_and_line_numbs:
        for dup in file_name_dups:

            # if previous_file_and_line == dup:
            #     set_appearance(ws3, row + 1, 1, 'fg_fill', 'D9D9D9')
            #     set_appearance(ws3, row + 1, 2, 'fg_fill', 'D9D9D9')


            # if file name is duplicate, highlight it
            if file_name_and_numb[0] == dup:
                set_appearance(ws3, row + 1, 1, 'fg_fill', 'FFC7CE')
                set_appearance(ws3, row + 1, 2, 'fg_fill', 'FFC7CE')


                # file namees with unique line numbers
                # if file_name_and_numb[0] in deduped_list:
                # if file_name_and_numb[0] in deduped_list:
                #     set_appearance(ws3, row + 1, 1, 'fg_fill', 'FFC7CE')
                #     set_appearance(ws3, row + 1, 2, 'fg_fill', 'FFC7CE')
                # else:
                #     # file names with matching line numbers
                #     set_appearance(ws3, row + 1, 1, 'fg_fill', 'D9D9D9')
                #     set_appearance(ws3, row + 1, 2, 'fg_fill', 'D9D9D9')

        row += 1




        # row2 = 1
        #
        # for item in file_names_and_line_numbs[0]:
        #     seen = set()
        #     #todo: keep this
        #     # identify the duplicate file+lineno combos
        #     for n in temp:
        #         if n in seen:
        #             ws3.cell(row=row2, column=3).value = n
        #             print("duplicate:", n)
        #             ws3.cell(row=row2, column=2).fill = PatternFill(bgColor="FFC7CE", fill_type="solid")
        #         else:
        #             seen.add(n)
        #     row2 += 1


def sort(v):  # for sorting
    return v[0], v[1]  # , v[7]
    #return v[0]


def import_xml_tags_ORIGINAL(suite_dat):
    row = 0

    score_xmls(suite_dat)
    ns = getattr(suite_data, 'name_space')

    ws = wb.get_sheet_by_name('XML Tags')
    row_count = ws.max_row
    col_count = ws.max_column

    tag_ids = [[0 for x in range(col_count)] for y in range(row_count)]

    for row_idx in ws.iter_rows():
        col = 0
        for cell in row_idx:
            tag_ids[row][col] = str(cell.value)
            col += 1
        row += 1

    setattr(suite_dat, 'tag_info', tag_ids)


def import_xml_tags(suite_dat):
    row = 0

    ws = wb.get_sheet_by_name('XML Tags')
    row_count = ws.max_row
    col_count = ws.max_column

    tag_ids = [[0 for x in range(col_count)] for y in range(row_count)]

    for row_idx in ws.iter_rows():
        col = 0
        for cell in row_idx:
            tag_ids[row][col] = str(cell.value)
            col += 1
        row += 1

    setattr(suite_dat, 'tag_info', tag_ids)


def auto_score(suite_dat):

    i = 0
    ns = {}

    opps_per_test_case = {}

    # get xml schema from vendor input file
    for idx, tag in enumerate(tag_ids):
        if idx == 1:
            finding_type_schema = tag_ids[idx][1]
        if idx == 2:
            file_name_schema = tag_ids[idx][1]
        if idx > 2:
            weakness_id_schemas.append(tag_ids[idx][1])

    # add namespace(s) to schemas
    finding_type = 'ns1:' + finding_type_schema.replace('/', '/ns1:')
    file_name = 'ns1:' + file_name_schema.replace('/', '/ns1:')

    for w_id in weakness_id_schemas:
        weakness_id_schemas[i] = 'ns1:' + w_id.replace('/', '/ns1:')
        i += 1

    # get acceptable weakness id groups
    acceptable_weaknesses = import_weakness_ids(cwe_no)
    for acceptable_weakness in acceptable_weaknesses:
        acceptable_groups.append(str(acceptable_weakness).split(':'))



    juliet_f_tc_type = False
    first_time_thru_project = True
    juliet_f_tc_hits = []
    juliet_f_tc_hits_deduped = []

    test_case_files = []
    acceptable_groups = []
    weakness_id_schemas = []
    de_duped_used_wid_list = []

    # get opp counts for juliet-false only
    if first_time_thru_project and test_case_type == 'Juliet' and test_case_t_f == 'FALSE':
        # get opp counts per test case
        first_time_thru_project = False
        # count hits per test cases (<= oc)
        juliet_test_case_path = os.path.join(os.getcwd(), 'juliet', os.path.dirname(filepath))
        opps_per_test_case = get_opp_counts_per_test_case(juliet_test_case_path)

    '''
    # read namespace from xml
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns["ns1"] = root.tag.split("}")[0].replace('{', '')
    '''

    tag_ids = import_xml_tags()

    # parse this xml
    for vuln in root.findall('./' + finding_type, ns):
        # weakness id parts
        kingdom = vuln.find(weakness_id_schemas[0], ns)
        type = vuln.find(weakness_id_schemas[1], ns)
        subtype = vuln.find(weakness_id_schemas[2], ns)
        fileline = vuln.find(file_name.rsplit('/', 1)[0], ns).attrib[
            'line']  # todo: 'line' hardcoded for now and not all tools may have this
        filepath = vuln.find(file_name.rsplit('/', 1)[0], ns).attrib['path']  # todo: 'path' hardcoded for now
        filename = os.path.basename(filepath)
        juliet_f_testcase_path = os.path.join(os.getcwd(), 'juliet', os.path.dirname(filepath))#todo: keep this for another possible approach. Faster?

        '''
        # get opp counts for juliet-false only
        if first_time_thru_project and test_case_type == 'Juliet' and test_case_t_f == 'FALSE':
            # get opp counts per test case
            first_time_thru_project = False
            # count hits per test cases (<= oc)
            juliet_test_case_path = os.path.join(os.getcwd(), 'juliet', os.path.dirname(filepath))
            opps_per_test_case = get_opp_counts_per_test_case(juliet_test_case_path)
        '''

        for group in acceptable_groups:
            found = False
            # valid groups
            if len(group) == 1:
                if kingdom.text in group[0]:
                    found = True
            elif len(group) == 2:
                if (kingdom.text in group[0]) and (type.text in group[1]):
                    found = True
            elif (len(group) == 3) and ('Subtype' in str(subtype)):#todo do i need this for the new version?
                if (kingdom.text in group[0]) and (type.text in group[1]) and (subtype.text in group[2]):
                    found = True

            if found:  # if found, this weakness id group, for this xml (project), is being used so we will count it as a hit
                # JULIET
                if test_case_type == 'juliet':
                    if test_case_t_f == 'TRUE':
                        # reduce filename to test case name by removing variant and file extension
                        filename = re.sub('[a-z]?\.\w+$', '', filename)
                    else:  # false
                        # if command line argument '-n = <normalize>', process the same as true
                        if normalize_juliet_false_scoring:
                            # treat false the same as true
                            filename = re.sub('[a-z]?\.\w+$', '', filename)
                        else:
                            juliet_f_tc_type = True
                            # accumulate all hits and line numbers
                            juliet_f_tc_hits.append([filepath, fileline])
                # KDM
                elif test_case_type == 'kdm':
                    filename = re.sub('[_a]?\.\w+$', '', filename)
                else:
                    print('NOT_Juliet_or_KDM_Test_Case')
                    continue

                test_case_files.append(filename)

                # todo: finish adding to vendor input sheet
                # used_wid_list.append([cwe_no, group])
                # de_duped_used_wid_list = remove_dups(used_wid_list)

    '''
    # copy file names for all hits
    juliet_f_tc_hits_deduped = [i[0] for i in juliet_f_tc_hits]
    juliet_f_tc_hits_deduped = set(juliet_f_tc_hits_deduped)

    # determine how many hits each file has
    for file in juliet_f_tc_hits_deduped:
        i, j = 0, 0
        # Count the number of hits each file received
        for file2 in juliet_f_tc_hits:
            if file2[0] == file:
                oc_count = file2[1]
                # each file will be given credit for a hit but only up to the number of 'FIX:'s (OC)s in the test case
                print('oc_count', oc_count)
                if oc_count > i:
                    i += 1  # used
                    j += 1
                else:
                    j += 1  # actual
                    print("COUNT_EXCEEDED_OC")

        print("FILE:-----", file, "HITS:-----", i, "OC:-----", oc_count)
        op_sheet_list.append([str(file), str(j), str(i), str(oc_count)])

    collect_hit_data(op_sheet_list)
   '''

    # get the unique hits for each file variant
    if juliet_f_tc_type:
        juliet_f_tc_hits_deduped = dedup_multi_dim_list(juliet_f_tc_hits)
        score = len(juliet_f_tc_hits_deduped)
    # get the unique hits for each set of test case files
    else:
        score = len(set(test_case_files))

    # return score, de_duped_used_wid_list, juliet_f_tc_hits_deduped, opps_per_test_case
    return score, de_duped_used_wid_list, juliet_f_tc_hits_deduped, juliet_f_testcase_path


def auto_score_ORIGINAL(xml_path, cwe_no, test_case_type, test_case_t_f):
    i = 0
    ns = {}

    opps_per_test_case = {}

    juliet_f_tc_type = False
    first_time_thru_project = True
    juliet_f_tc_hits = []
    juliet_f_tc_hits_deduped = []

    test_case_files = []
    acceptable_groups = []
    weakness_id_schemas = []
    de_duped_used_wid_list = []

    '''
    # get opp counts for juliet-false only
    if first_time_thru_project and test_case_type == 'Juliet' and test_case_t_f == 'FALSE':
        # get opp counts per test case
        first_time_thru_project = False
        # count hits per test cases (<= oc)
        juliet_test_case_path = os.path.join(os.getcwd(), 'juliet', os.path.dirname(filepath))
        opps_per_test_case = get_opp_counts_per_test_case(juliet_test_case_path)
    '''

    # read namespace from xml
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns["ns1"] = root.tag.split("}")[0].replace('{', '')

    tag_ids = import_xml_tags()

    # get xml schema from vendor input file
    for idx, tag in enumerate(tag_ids):
        if idx == 1:
            finding_type_schema = tag_ids[idx][1]
        if idx == 2:
            file_name_schema = tag_ids[idx][1]
        if idx > 2:
            weakness_id_schemas.append(tag_ids[idx][1])

    # add namespace(s) to schemas
    finding_type = 'ns1:' + finding_type_schema.replace('/', '/ns1:')
    file_name = 'ns1:' + file_name_schema.replace('/', '/ns1:')

    for w_id in weakness_id_schemas:
        weakness_id_schemas[i] = 'ns1:' + w_id.replace('/', '/ns1:')
        i += 1

    # get acceptable weakness id groups
    acceptable_weaknesses = import_weakness_ids(cwe_no)
    for acceptable_weakness in acceptable_weaknesses:
        acceptable_groups.append(str(acceptable_weakness).split(':'))

    # parse this xml
    for vuln in root.findall('./' + finding_type, ns):
        # weakness id parts
        kingdom = vuln.find(weakness_id_schemas[0], ns)
        type = vuln.find(weakness_id_schemas[1], ns)
        subtype = vuln.find(weakness_id_schemas[2], ns)
        fileline = vuln.find(file_name.rsplit('/', 1)[0], ns).attrib[
            'line']  # todo: 'line' hardcoded for now and not all tools may have this
        filepath = vuln.find(file_name.rsplit('/', 1)[0], ns).attrib['path']  # todo: 'path' hardcoded for now
        filename = os.path.basename(filepath)
        juliet_f_testcase_path = os.path.join(os.getcwd(), 'juliet', os.path.dirname(filepath))

        '''
        # get opp counts for juliet-false only
        if first_time_thru_project and test_case_type == 'Juliet' and test_case_t_f == 'FALSE':
            # get opp counts per test case
            first_time_thru_project = False
            # count hits per test cases (<= oc)
            juliet_test_case_path = os.path.join(os.getcwd(), 'juliet', os.path.dirname(filepath))
            opps_per_test_case = get_opp_counts_per_test_case(juliet_test_case_path)
        '''

        for group in acceptable_groups:
            found = False
            # valid groups
            if len(group) == 1:
                if kingdom.text in group[0]:
                    found = True
            elif len(group) == 2:
                if (kingdom.text in group[0]) and (type.text in group[1]):
                    found = True
            elif (len(group) == 3) and ('Subtype' in str(subtype)):
                if (kingdom.text in group[0]) and (type.text in group[1]) and (subtype.text in group[2]):
                    found = True

            if found:  # if found, this weakness id group, for this xml (project), is being used so we will count it as a hit
                # JULIET
                if test_case_type == 'juliet':
                    if test_case_t_f == 'TRUE':
                        # reduce filename to test case name by removing variant and file extension
                        filename = re.sub('[a-z]?\.\w+$', '', filename)
                    else:  # false
                        # if command line argument '-n = <normalize>', process the same as true
                        if normalize_juliet_false_scoring:
                            # treat false the same as true
                            filename = re.sub('[a-z]?\.\w+$', '', filename)
                        else:
                            juliet_f_tc_type = True
                            # accumulate all hits and line numbers
                            juliet_f_tc_hits.append([filepath, fileline])
                # KDM
                elif test_case_type == 'kdm':
                    filename = re.sub('[_a]?\.\w+$', '', filename)
                else:
                    print('NOT_Juliet_or_KDM_Test_Case')
                    continue

                test_case_files.append(filename)

                # todo: finish adding to vendor input sheet
                # used_wid_list.append([cwe_no, group])
                # de_duped_used_wid_list = remove_dups(used_wid_list)

    '''
    # copy file names for all hits
    juliet_f_tc_hits_deduped = [i[0] for i in juliet_f_tc_hits]
    juliet_f_tc_hits_deduped = set(juliet_f_tc_hits_deduped)

    # determine how many hits each file has
    for file in juliet_f_tc_hits_deduped:
        i, j = 0, 0
        # Count the number of hits each file received
        for file2 in juliet_f_tc_hits:
            if file2[0] == file:
                oc_count = file2[1]
                # each file will be given credit for a hit but only up to the number of 'FIX:'s (OC)s in the test case
                print('oc_count', oc_count)
                if oc_count > i:
                    i += 1  # used
                    j += 1
                else:
                    j += 1  # actual
                    print("COUNT_EXCEEDED_OC")

        print("FILE:-----", file, "HITS:-----", i, "OC:-----", oc_count)
        op_sheet_list.append([str(file), str(j), str(i), str(oc_count)])

    collect_hit_data(op_sheet_list)
   '''

    # get the unique hits for each file variant
    if juliet_f_tc_type:
        juliet_f_tc_hits_deduped = dedup_multi_dim_list(juliet_f_tc_hits)
        score = len(juliet_f_tc_hits_deduped)
    # get the unique hits for each set of test case files
    else:
        score = len(set(test_case_files))

    # return score, de_duped_used_wid_list, juliet_f_tc_hits_deduped, opps_per_test_case
    return score, de_duped_used_wid_list, juliet_f_tc_hits_deduped, juliet_f_testcase_path


def get_opp_counts_per_test_case(juliet_test_case_path):
    opp_counts = {}

    # for root, dirs, files in os.walk(juliet_tc_path_f):
    for root, dirs, files in os.walk(juliet_test_case_path):

        for file in files:
            opp_count = 0
            if file.endswith(".c"):
                with open(os.path.join(root, file), 'r') as inF:
                    for line in inF:
                        if 'FIX' in line:
                            opp_count += 1
                            # todo: need to get the line number

                            # $$$$$$$$$$$$$$$$$$$
                            # with open(filename) as myFile:
                            #     for num, line in enumerate(myFile, 1):
                            #         if lookup in line:
                            #             print
                            #             'found at line:', num
                            # $$$$$$$$$$$$$$$$$$$$

                # get test case name by removing variant and file extension
                test_case_name = re.sub("[a-z]?\.\w+$", "", file)
                test_case_full_path = os.path.join(root, test_case_name)

                # if test case name not in the list, add it
                if opp_counts.get(test_case_full_path, 'None') == 'None':
                    opp_counts.update({test_case_full_path: opp_count})

                # if test case name is in the list, add this new value to the existing value
                else:
                    current_value = opp_counts[test_case_full_path]
                    updated_value = opp_count + current_value
                    opp_counts.update({test_case_full_path: updated_value})

    # return opp counts by test case name
    return opp_counts  # todo: consider sorting these for speed?


def get_opp_counts_per_test_case_ORIGINAL(juliet_test_case_path):
    opp_counts = {}

    # for root, dirs, files in os.walk(juliet_tc_path_f):
    for root, dirs, files in os.walk(juliet_test_case_path):

        for file in files:
            opp_count = 0
            if file.endswith(".c"):
                with open(os.path.join(root, file), 'r') as inF:
                    for line in inF:
                        if 'FIX' in line:
                            opp_count += 1

                # get test case name by removing variant and file extension
                test_case_name = re.sub("[a-z]?\.\w+$", "", file)
                test_case_full_path = os.path.join(root, test_case_name)

                # if test case name not in the list, add it
                if opp_counts.get(test_case_full_path, 'None') == 'None':
                    opp_counts.update({test_case_full_path: opp_count})

                # if test case name is in the list, add this new value to the existing value
                else:
                    current_value = opp_counts[test_case_full_path]
                    updated_value = opp_count + current_value
                    opp_counts.update({test_case_full_path: updated_value})

    # return opp counts by test case name
    return opp_counts  # todo: consider sorting these for speed?


def get_opp_counts_per_file(file_path):
    opp_counts = {}

    for root, dirs, files in os.walk(file_path):

        for file in files:
            opp_count = 0
            if file.endswith(".c"):
                with open(root + "\\" + file, 'r') as inF:
                    for line in inF:
                        # if 'FIX' in line:
                        # if line.lstrip().startswith('good') and line.endswith(''):
                        if line.lstrip().startswith('good') and line.rstrip().endswith('();'):
                            opp_count += 1
                            print('LINE============', line, 'in=======', file)
                            # todo: this works. do it for only files that hit?
                # test_case_name = re.sub("[a-z]?\.\w+$", "", file)

                # testcase name and opp count to list or update if already there
                if opp_counts.get(file, 'None') == 'None':
                    opp_counts.update({file: opp_count})
                else:
                    current_value = opp_counts[file]
                    updated_value = opp_count + current_value
                    opp_counts.update({file: updated_value})
                    # print("updated_value", file, updated_value)

    # return opp counts by test case name
    return opp_counts  # consider sorting these for speed?


def opp_counts_by_file_ORIGINAL(project_path):  # todo: argument = project path

    opp_counts = {}
    # opp_counts.clear() to delete all

    suite_path = os.getcwd()

    # keep for now since this gets all test cases
    # juliet_tc_path_f = suite_path + "\\" + "juliet\F"

    juliet_tc_path_f = os.path.join(suite_path + "\\juliet\\" + project_path)

    for root, dirs, files in os.walk(juliet_tc_path_f):

        for file in files:
            opp_count = 0
            if file.endswith(".c"):
                with open(root + "\\" + file, 'r') as inF:
                    for line in inF:
                        if 'FIX' in line:
                            opp_count += 1

                # test_case_name = re.sub("[a-z]?\.\w+$", "", file)

                # testcase name and opp count to list or update if already there
                if (opp_counts.get(file, 'None') == 'None'):
                    opp_counts.update({file: opp_count})
                else:
                    current_value = opp_counts[file]
                    updated_value = opp_count + current_value
                    opp_counts.update({file: updated_value})
                    # print("updated_value", file, updated_value)

    # return opp counts by test case name
    return opp_counts  # consider sorting these for speed?


def remove_dups(d):
    new_d = []
    for x in d:
        if x not in new_d:
            new_d.append(x)
    return new_d


def write_details(data_details):
    #########################################################################################################
    detail_sheet_titles = ['CWE', 'Type', 'T/F', 'TC', 'Hits', '%Hits', 'XML', 'TC Path', 'RAW Project File']
    #########################################################################################################

    row = 1

    attribute_list = ['cwe_id_padded', 'tc_type', 'true_false', 'tc_count', 'num_of_hits', 'percent_hits',
                      'new_xml_name', 'tc_path', 'scan_data_file']


    # perform multi-column sorts
    #scan_data.sort(key=sort)

    # freeze first row and column
    ws2.freeze_panes = ws2['B2']

    # write column headers
    for idx, title in enumerate(detail_sheet_titles):
        set_appearance(ws2, row, idx + 1, 'fg_fill', 'F4B084')
        ws2.cell(row=1, column=idx + 1).value = title
        ws2.cell(row=1, column=idx + 1).alignment = Alignment(horizontal="center")

    # write detailed data
    for j, attrib in enumerate(attribute_list):
        for i, xml_data in enumerate(data_details.xml_projects):
            # juliet or kdm
            tc_attrib = getattr(data_details.xml_projects[i], attrib)
            ws2.cell(row=i + 2, column=j + 1).value = tc_attrib
            set_appearance(ws2, i + 2, j + 2, 'fg_fill', 'FFFFFF')
            ws2.cell(row=i + 2, column=j + 1).alignment = Alignment(horizontal="left")

    #todo: keep this stuff until colors are implemented
    '''
    for data in scan_data:

        row += 1

        # write data to sheets
        for idx, data_id in enumerate(data):
            ws2.cell(row=row, column=idx + 1).value = data_id

            set_appearance(ws2, row, idx + 1, 'fg_fill', 'FFFFFF')
            ws2.cell(row=row, column=2).alignment = Alignment(horizontal="right")

        # set appearance & style
        if data[3] > 0:  # if hits > 0
            if data[7] == "TRUE":  # if true
                set_appearance(ws2, row, 4, 'font_color', '548235')
                set_appearance(ws2, row, 5, 'font_color', '548235')
            if data[7] == "FALSE":  # if false
                set_appearance(ws2, row, 4, 'font_color', 'C00000')
                set_appearance(ws2, row, 5, 'font_color', 'C00000')
        else:  # no hits
            set_appearance(ws2, row, 4, 'fg_fill', 'D9D9D9')
            set_appearance(ws2, row, 5, 'fg_fill', 'D9D9D9')
    '''


def write_details_ORIGINAL(scan_data):
    #########################################################################################################
    detail_sheet_titles = ['CWE', 'Type', 'TC', 'Hits', '%Hits', 'XML', 'TC Path', 'T/F', 'RAW Project File']
    #########################################################################################################

    row = 1

    # perform multi-column sorts
    scan_data.sort(key=sort)

    # freeze first row and column
    ws2.freeze_panes = ws2['B2']

    # write column headers
    for idx, title in enumerate(detail_sheet_titles):
        set_appearance(ws2, row, idx + 1, 'fg_fill', 'F4B084')
        ws2.cell(row=1, column=idx + 1).value = title
        ws2.cell(row=1, column=idx + 1).alignment = Alignment(horizontal="center")

    for data in scan_data:

        row += 1

        # write data to sheets
        for idx, data_id in enumerate(data):
            ws2.cell(row=row, column=idx + 1).value = data_id

            set_appearance(ws2, row, idx + 1, 'fg_fill', 'FFFFFF')
            ws2.cell(row=row, column=2).alignment = Alignment(horizontal="right")

        # set appearance & style
        if data[3] > 0:  # if hits > 0
            if data[7] == "TRUE":  # if true
                set_appearance(ws2, row, 4, 'font_color', '548235')
                set_appearance(ws2, row, 5, 'font_color', '548235')
            if data[7] == "FALSE":  # if false
                set_appearance(ws2, row, 4, 'font_color', 'C00000')
                set_appearance(ws2, row, 5, 'font_color', 'C00000')
        else:  # no hits
            set_appearance(ws2, row, 4, 'fg_fill', 'D9D9D9')
            set_appearance(ws2, row, 5, 'fg_fill', 'D9D9D9')


def write_summary(scan_data):
    #########################################################################################################
    detail_sheet_titles = ['CWE', 'Type', 'TC', 'Hits', '%Hits', 'XML', 'TC Path', 'T/F', 'RAW Project File']
    #########################################################################################################

    row = 1
    # scan_data.sort()#todo: will need to sort new data?

    cwes = []

    summary_sheet_titles = ['CWE', 'TC TRUE', 'TC FALSE', 'TP', 'FP', 'Precision', 'Recall']

    ws1.freeze_panes = ws1['H2']

    # write column headers
    for idx, title in enumerate(summary_sheet_titles):
        set_appearance(ws1, row, idx + 1, 'fg_fill', 'E6B8B7')
        ws1.cell(row=1, column=idx + 1).value = title
        ws1.cell(row=1, column=idx + 1).alignment = Alignment(horizontal="center")

    for xml_project in scan_data.xml_projects:
        cwes.append(getattr(xml_project, 'cwe_id_padded'))

    unique_cwes = list(set(cwes))
    unique_cwes.sort()

    # collect data for each cwe and summarize
    for cwe in unique_cwes:

        tc_t = tc_f = tp = fp = prec = rec = 0

        row += 1

        for xml_project in scan_data.xml_projects:
            if cwe == getattr(xml_project, 'cwe_id_padded'):
                if 'TRUE' == getattr(xml_project, 'true_false'):
                    tc_t += getattr(xml_project, 'tc_count')
                    tp += getattr(xml_project, 'num_of_hits')
                elif 'FALSE' == getattr(xml_project, 'true_false'):
                    tc_f += getattr(xml_project, 'tc_count')
                    fp += getattr(xml_project, 'num_of_hits')
                    # todo: add break or continue to speed this up?

        # for row1 in ws1.iter_rows('A1:C2'):
        for row1 in ws1.iter_rows():
            for cell in row1:
                if cell.col_idx > 1:
                    if tp == 0:
                        set_appearance(ws1, row, cell.col_idx - 1, 'fg_fill', 'F2F2F2')
                    else:
                        set_appearance(ws1, row, cell.col_idx - 1, 'fg_fill', 'FFFFFF')

                    ws1.cell(row=row, column=cell.col_idx - 1).alignment = Alignment(horizontal='right')

        set_appearance(ws1, row, 1, 'fg_fill', 'C6C6C6')

        # PRECISION
        if tp + fp != 0:
            prec = tp / (tp + fp)
            ws1.cell(row=row, column=6).value = round(prec, 2)
            ws1.cell(row=row, column=6).number_format = '0.00'
        else:
            ws1.cell(row=row, column=6).value = 'N/A'
            ws1.cell(row=row, column=6).alignment = Alignment(horizontal='right')

        # RECALL
        recall = tp / tc_t

        # todo: format numbers with commas
        ws1.cell(row=row, column=1).value = cwe
        ws1.cell(row=row, column=2).value = tc_t
        ws1.cell(row=row, column=3).value = tc_f
        ws1.cell(row=row, column=4).value = tp
        ws1.cell(row=row, column=5).value = fp
        ws1.cell(row=row, column=7).value = recall
        #todo: loop this
        ws1.cell(row=row, column=7).number_format = '0.00'
        ws1.cell(row=row, column=2).number_format = '#,##0'
        ws1.cell(row=row, column=3).number_format = '#,##0'
        ws1.cell(row=row, column=4).number_format = '#,##0'
        ws1.cell(row=row, column=5).number_format = '#,##0'


def set_appearance(ws_id, row_id, col_id, style_id, color_id):
    cell = ws_id.cell(row=row_id, column=col_id)

    if style_id == 'font_color':
        font_color = Font(color=color_id)
        cell.font = font_color
    if style_id == 'fg_fill':
        fill_color = PatternFill(fgColor=color_id, fill_type='solid')
        cell.fill = fill_color

    # build thin border for all styles
    thin_border = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'),
                         bottom=Side(style='thin'))
    cell.border = thin_border


def create_summary_chart():
    chart1 = BarChart()
    chart1.type = 'col'
    chart1.style = 11
    chart1.y_axis.title = 'Score'
    chart1.x_axis.title = 'CWE Number'
    data = Reference(ws1, min_col=6, min_row=1, max_row=52, max_col=7)
    cats = Reference(ws1, min_col=1, min_row=2, max_row=52)
    chart1.add_data(data, titles_from_data=True)
    chart1.set_categories(cats)
    chart1.shape = 4
    chart1.title = 'Protection Profile Scores'
    auto_axis = True
    chart1.y_axis.scaling.min = 0
    chart1.y_axis.scaling.max = 1
    # chart1.height = 15
    # chart1.width = 45
    chart1.height = 15
    chart1.width = 40
    # chart1.set_x_axis({'num_font':  {'rotation': 270}})

    ws1.add_chart(chart1, 'H2')


def write_opp_counts_to_sheet(suite_dat):
    test_case_files_and_line_that_hit = []

    for xml_project in suite_dat.xml_projects:
        test_case_files_and_line_that_hit.append(getattr(xml_project, 'test_case_files_and_line_that_hit'))


        # for idx, file in enumerate(test_case_files_and_line_that_hit):
        #     # file_name = str(file[0])
        #     # line_no = str(file[1])
        #
        #     file_name = file[idx][0]
        #     line_no = file[idx][1]
        #
        #     test_case_files_and_line_that_hit.append([file_name, line_no])

    collect_hit_data(test_case_files_and_line_that_hit)


def write_opp_counts_to_sheet_ORIGINAL(juliet_f_hits):
    op_sheet_list = []

    for file in juliet_f_hits:
        file_name = str(file[0])
        line_no = str(file[1])

        op_sheet_list.append([file_name, line_no])

    collect_hit_data(op_sheet_list)


def dedup_multi_dim_list(mylist):
    seen = set()
    newlist = []
    for item in mylist:
        t = tuple(item)
        if t not in seen:
            newlist.append(item)
            seen.add(t)
    return newlist


def import_weakness_ids(suite_dat):
    # todo: consider consolidating this function with 'import_xml_tags'
    row = 0

    ws = wb.get_sheet_by_name('Weakness IDs')
    row_count = ws.max_row
    col_count = ws.max_column

    weakness_ids = [[0 for x in range(col_count)] for y in range(row_count)]

    # put all weakness ids into 'weakness_ids' list
    for row_idx in ws.iter_rows():
        col = 0
        for cell in row_idx:
            weakness_ids[row][col] = str(cell.value)
            col += 1
        row += 1
        # create a full list for the suite object
        setattr(suite_dat, 'acceptable_weakness_ids_full_list', weakness_ids)

    # add weakness ids to each xml object
    for i, xml_project in enumerate(suite_dat.xml_projects):
        cwe_num = getattr(xml_project, 'cwe_num')
        for weakness_id in weakness_ids:
            if weakness_id[0] == cwe_num:
                setattr(xml_project, 'acceptable_weakness_ids', weakness_id)
                break


def remove_duplicates(numbers):
    newlist = []
    for number in numbers:
        if number not in newlist:
            newlist.append(number)
    return newlist


def flatten(lis):
    for item in lis:
        if isinstance(item, Iterable) and not isinstance(item, basestring):
            for x in flatten(item):
                yield x
        else:
            yield item
    return lis


def get_used_wids(scan_data):
    cwes = []

    for xml_project in scan_data.xml_projects:
        cwes.append(getattr(xml_project, 'cwe_id_padded'))
    unique_cwes = list(set(cwes))
    unique_cwes.sort()  # todo: dont think this is necessary

    for cwe in unique_cwes:

        used_wids_per_cwe = []
        new_list2 = []

        # go thru each project looking for this cwe
        for xml_project in suite_data.xml_projects:

            # if the cwe for this project matches, get it's wids
            if cwe == getattr(xml_project, 'cwe_id_padded'):
                used_wids_per_cwe.append(getattr(xml_project, 'used_wids'))
                # put all of the pieces into a single dimension array
                for wid in used_wids_per_cwe:
                    new_list2.append(wid)
            else:
                continue

        new_list2 = [item for sublist in new_list2 for item in sublist]
        new_list2 = list(set(new_list2))
        updated_list = getattr(scan_data, 'used_wids_per_cwe')

        updated_list.append([cwe, new_list2])

        setattr(scan_data, 'used_wids_per_cwe', updated_list)
        # todo: paint the vendor input wids if found (or not found)


if __name__ == '__main__':

    data = []
    juliet_f_counts = []

    py_common.print_with_timestamp('--- STARTED SCORING ---')

    parser = argparse.ArgumentParser(description='A script used to score all SCA tools.')
    # required
    parser.add_argument('suite', help='The suite number being scanned (i.e. 1 - 10)', type=int)
    # optional
    parser.add_argument('-n', dest='normalize', action='store_true', help='Enter \'\-n\' option for normalized score')

    args = parser.parse_args()
    suite_number = args.suite
    suite_path = os.getcwd()
    scaned_data_path = os.path.join(suite_path, 'scans')
    new_xml_path = os.path.join(suite_path, XML_OUTPUT_DIR)
    if args.normalize:
        normalize_juliet_false_scoring = True
    else:
        normalize_juliet_false_scoring = False

    # create scorecard from vendor input file
    time = strftime('scorecard-fortify-c_%m-%d-%Y_%H.%M.%S' + '_suite_' + str(suite_number).zfill(2))
    vendor_input = os.path.join(suite_path, 'vendor-input-' + TOOL_NAME + '-c.xlsx')
    scorecard = os.path.join(suite_path, time) + '.xlsx'
    shutil.copyfile(vendor_input, scorecard)

    # add sheets and format
    wb = load_workbook(scorecard)
    ws1 = wb.create_sheet('Summary', 0)
    ws2 = wb.create_sheet('Detailed Data', 1)
    ws3 = wb.create_sheet('Opportunity Counts', 5)

    format_workbook()

    # get scan data and save it to the new xml path
    #data = get_data(scaned_data_path, new_xml_path)

    # instanciate a suite object and get suite data
    suite_data = Suite(scaned_data_path, new_xml_path, TOOL_NAME)

    # import tag data
    import_xml_tags(suite_data)
    # import weakness ids
    import_weakness_ids(suite_data)
    # score the xml projects
    score_xmls(suite_data)
    # get a summary of all used wids
    get_used_wids(suite_data)

    # write to sheets
    write_details(suite_data)
    write_summary(suite_data)
    create_summary_chart()
    collect_hit_data(suite_data)

    wb.active = 0
    wb.save(scorecard)

    py_common.print_with_timestamp('--- FINISHED SCORING ---')
