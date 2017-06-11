import os
import sys
from jira.client import JIRA
from jira.exceptions import JIRAError
import re
jira_server = "https://page123.atlassian.net"
jira_user = "vada@wmail.club"
jira_password = "password123"
jira_server = {'server': jira_server}
jira = JIRA(options=jira_server, basic_auth=(jira_user, jira_password))


def get_scenarios_with_values(scenario_table_rows, variables_names, scenario_template):
    scenarios_to_save = {}
    table_values_rows = len(scenario_table_rows)
    for scenario_row in range(0, table_values_rows):
        d = {}
        for name, value in zip(variables_names, scenario_table_rows[scenario_row]):
            d[name] = value.replace(' ', '_') if name == '${title}' else value

        scenarios_to_save[d['${title}']] = multiwordReplace(scenario_template, d)
    return scenarios_to_save


def multiwordReplace(text, wordDic):
    rc = re.compile('|'.join(map(re.escape, wordDic)))
    def translate(match):
        return wordDic[match.group(0)]
    return rc.sub(translate, text)


def get_ticket_status(issue_id):
    return jira.issue(issue_id).fields.status.name


def get_issue_fields(issue_id):
    issue = jira.issue(issue_id)
    # print 'project key: ', issue.fields.project.key
    # print 'issue.fields.status.name', issue.fields.status.name
    fields_to_return = {
        'project': issue.fields.project.key,
        'issuetype':{
            'name': issue.fields.issuetype.name,
        },
        'description': '',
        'reporter':{
            'name': issue.fields.reporter.name
        },
        'priority':{
            'name': issue.fields.priority.name,
        },
        # 'status': {
        #     'name': str(issue.fields.status.name),
        # },
        'labels': [str(label) for label in issue.fields.labels],
        'summary':'',
        }
    return str(issue.fields.description).split('\r\n'), fields_to_return


def get_table_index(description):
    table_index = -1
    description_length = len(description)
    for index in range(0,description_length):
        p = re.compile('^(\$\{[a-zA-Z0-9\-]+\}(\|)?)+')
        m = p.match(description[index])
        if m:
            table_index = index
            break
    return table_index


def get_variable_names(description, variables_index):
    variables_line = description[variables_index:variables_index + 1][0]
    p = re.compile('^(\$\{[a-zA-Z0-9\-]+\}(\|)?)+')
    m = p.match(variables_line)
    if m:
        variables = ''.join(str(x).replace(' ', '') for x in variables_line).split('|')
        return variables
    else:
        sys.exit(-1)


def get_variable_values(description, variables_index):
    scenario_table_rows = ['|'.join(re.sub('^([ ]{1,})', '', re.sub('[ ]+$', '', y))
                                    for y in x.split('|')) for x in description[variables_index+ 1:]]
    return [str(table_row).split('|') for table_row in scenario_table_rows]


def get_variable_values_count_per_line(variable_lines):
    count = {}
    for line_index in range(0, len(variable_lines)):
        count[line_index] = sum([ 1 for x in variable_lines[line_index]
                                  if len(str(re.sub('^([ ]{1,})', '', re.sub('[ ]+$', '', x))))])
    return count


def get_scenario_template(description, variables_index):
    return '\r\n'.join(description[0:variables_index])


def check_variable_lines(description_lines, variables_line_index):
    variable_values_count = get_variable_values_count_per_line(get_variable_values(description_lines,
                                                                                   variables_line_index))
    variable_names_count = len(get_variable_names(description_lines, variables_line_index))
    missing_lines = {}
    for key, val in variable_values_count.iteritems():
        if val != variable_names_count:
            missing_lines[variables_line_index + 2 + key] = \
                '------------------------------------------------------------------------' \
                '\r\nMissing variable value in line with index: {}' \
                '\r\nLine "{}"' \
                '\r\nMismatch between number of defined variables ({}) and its values ({})' \
                '\r\n------------------------------------------------------------------------'.format(
                    variables_line_index + 2 + key,
                    description_lines[variables_line_index + 1 + key],
                    variable_names_count, val)
    if missing_lines:
        for key, val in missing_lines.iteritems():
            print val
        sys.exit(-1)


def clone_issue(issue_key_to_be_cloned, fields_to_use):
    new_issue = jira.create_issue(fields=fields_to_use)
    transitions = jira.transitions(new_issue.key)
    current_status = str(jira.issue(issue_key_to_be_cloned).fields.status.name)
    # new_issue = 'TEST-1000'
    # parent_issue = 'TEST-2000'
    #
    # jira.create_issue_link(
    #     type="Duplicate",
    #     inwardIssue=new_issue,
    #     outwardIssue=parent_issue,
    #     comment={
    #         "body": "Linking '%s' --&gt; '%s'" % (new_issue, parent_issue),
    #     }
    # )
    for t in transitions:
        if str(t['name']) == current_status:
            jira.transition_issue(new_issue.key, str(t['id']))
    return new_issue.key


def create_sub_tickets(source_ticket_id):
    description_lines, my_fields = get_issue_fields(issue_id=source_ticket_id)
    variables_line_index = get_table_index(description_lines)
    if variables_line_index > 0:
        check_variable_lines(description_lines, variables_line_index)
        scenarios_valid = get_scenarios_with_values(get_variable_values(description_lines, variables_line_index),
                                                    get_variable_names(description_lines, variables_line_index),
                                                    get_scenario_template(description_lines, variables_line_index))
        clones = []
        for scenario_summary, scenario in scenarios_valid.iteritems():
            with open('D:\\testy\\'+scenario_summary+'.robot', 'w') as out:
                scenario_to_save = scenario_summary
                scenario_to_save += os.linesep
                scenario_to_save += scenario.replace('\r\n','\n')
                out.write(scenario_to_save)

            my_fields['summary'] = scenario_summary
            my_fields['description'] = scenario
            issue_id = clone_issue(source_ticket_id, my_fields)
            clones.append(issue_id)
        print 'clones:', clones

    else:
        print 'Variables block missing'
        sys.exit(0)


def check_ticket_status(ticket_id):
    try:
        ticket = jira.issue(id=ticket_id)
        return True if ticket.key else False
    except JIRAError as err:
        err_lines = [x.strip() for x in str(err).split('response')[0].split('\n') if len(x) > 0]
        err_lines = [x for x in err_lines if 'text' in x ]
        print ''.join(err_lines).replace('text: Issue','Sorry, issue with given id "{}"'.format(ticket_id))
        sys.exit(-1)


if __name__ == '__main__':
    if 2 >= len(sys.argv) > 1:
        ticket_id = sys.argv[1]
        ticket_regex = '^[a-zA-Z]+-[0-9]+$'
        if re.match(ticket_regex, ticket_id):
            check_ticket_status(ticket_id)
            create_sub_tickets(source_ticket_id=ticket_id)
            status = 0
        else:
            print 'Provided ticket id "{}" is invalid. Please fix. ' \
                  '\r\n(Format of ticket id is: {})'.format(ticket_id, ticket_regex)
            status = -1
    else:
        print 'Unsupported number of cmd line arguments'
        status = -1
    sys.exit(status)
