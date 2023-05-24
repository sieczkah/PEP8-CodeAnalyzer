import pathlib
import argparse
from _ast import ClassDef, FunctionDef, expr
import ast
import re
from typing import Generator, List, Optional, Tuple, Dict


class Line:
    """Represents a line of code for static code analysis.

    Represents a line of code for static code analysis. Implements validation functions
    that validate if provided line follows PEP8 styling guide rules.

    Attributes:
        line (str): A string representing a line of code.
        line_index (int): An integer representing the index of the line of code. By default, is 1.
        preceding_blank_lines (int): The number of blank lines preceding line of code. By default, is 0.
        length (int): The length of the line.
        indentation (int): The indentation level of the line.
        code_part (str): The code part of the line.
        comment_part (str): The comment part of the line.
        code_comment_spaces (int): The number of spaces between the code and comment parts.

    """

    def __init__(self, line: str, line_index: int = 1, preceding_blank_lines: int = 0) -> None:
        """
        Initialize a Line object.

        Args:
            line ():  The line of code.
            line_index (): Index of the provided line of code. By default, 1.
            preceding_blank_lines (): The number of blank lines preceding line of code. By default, is 0.
        """
        self.line = line
        self.line_index = line_index
        self.preceding_blank_lines = preceding_blank_lines
        self.length = len(line)
        self.indentation = self.get_indentation(line)
        self.code_part, self.comment_part, self.code_comment_spaces = self.split_line_to_code_comment(
            self.line)

    def get_issues(self) -> List:
        """
        Get a list of a PEP8 styling issues found in the line.

        Returns:
            A list of string messages alerting of the occurred issue.

        """
        line_pep_issues = [self.invalid_length(),
                           self.invalid_indentation(),
                           self.ends_with_semicolon(),
                           self.invalid_inline_comment_spacing(),
                           self.todo_in_comment(),
                           self.invalid_preceding_blanklines(),
                           self.invalid_spaces_def_class_construction()
                           ]
        return list(filter(bool, line_pep_issues))

    def invalid_length(self) -> Optional[str]:
        """
        Check if the line length is greater than 79 characters.

        Returns:
            The issue message if the line length is greater than 79, None otherwise.
        """
        if self.length > 79:
            return 'S001 Too long'

    def invalid_indentation(self) -> Optional[str]:
        """
        Check if indentation of line is a multiple of four.

        Returns:
            The issue message if the line indentation is not multiple of four, None otherwise.
        """
        if self.indentation % 4 != 0:
            return 'S002 Indentation is not a multiple of four'

    def ends_with_semicolon(self) -> Optional[str]:
        """
        Checks if the code part of the line ends with a semicolon.

        Returns:
            The issue message if the code part of the line ends with semicolon, None otherwise.
        """
        if self.code_part.rstrip().endswith(';'):
            return 'S003 Unnecessary semicolon'

    def invalid_inline_comment_spacing(self) -> Optional[str]:
        """
        Checks if there is at least two spaces between code part of the line and inline comment.

        Returns:
            The issue message if there is at least two spaces between code part of the line and inline comment,
            None otherwise.
        """
        if self.code_part and self.comment_part and self.code_comment_spaces < 2:
            return 'S004 At least two spaces required before inline comments'

    def todo_in_comment(self) -> Optional[str]:
        """
        Checks if TODO appears in the comment part of the line.

        Returns:
            The alert message if there is a TODO in the comment part, otherwise None.
        """
        if 'TODO' in self.comment_part.upper():
            return 'S005 TODO found'

    def invalid_preceding_blanklines(self) -> Optional[str]:
        """
        Checks if there are more than two blank lines used before this line.

        Returns:
            Returns an issue message if there are more than two blank lines used before this line,
            otherwise returns None.
        """
        if self.preceding_blank_lines > 2:
            return 'S006 More than two blank lines used before this line'

    def invalid_spaces_def_class_construction(self) -> Optional[str]:
        """
        Checks if there is exactly one space between key word def | class and the name.

        Returns:
            Returns an issue message if there are too many spaces after 'def' or 'class' keywords,
            otherwise returns None
        """
        match = re.search(r'(def|class)\s+(\w+)', self.code_part)
        if match:
            construct = match.group(1)
            name = match.group(2)
            spaces = len(match.group(0)) - len(construct) - len(name)
            if spaces > 1:
                return f'S007 Too many spaces after {construct}'

    @staticmethod
    def split_line_to_code_comment(line: str) -> Tuple[str, str, int]:
        """
        Splits a line into code part and comment part.

        Using regex spits a line into a code part that contains python syntax, and a comment part that includes
        everything that appeared after '#'.

        Args:
            line: The line of code to be split.

        Returns:
            A tuple containing code part, comment part, and calculated spaces between them.
        """
        # Looking for comment part of the line, matches everything that appears after '#'
        # (?<!') - ensures match is not inside '' quotes
        # (?<!") - ensures match is not inside "" quotes
        # #(.*) - matches everything that appears after # symbol
        comment_match = re.search(r"""(?<!')(?<!")#(.*)""", line)
        comment_part = comment_match.group() if comment_match else ''
        # getting code_part by right stripping line of the comment part
        code_part = line.rstrip(comment_part).rstrip()
        # getting spaces between code and comment part by subtracting length form line
        spaces_between_code_comment = len(
            line) - len(code_part) - len(comment_part)

        return code_part, comment_part, spaces_between_code_comment

    @staticmethod
    def get_indentation(line: str) -> int:
        """
        Calculates the number of spaces used before the line as indentation.

        Args:
            line: The line of code.

        Returns:
            The number of spaces used as indentation.
        """
        match = re.match(r'^( )*', line)
        return len(match.group())


class ASTNodeAnalyzer(ast.NodeVisitor):
    """
    An AST (Abstract Syntax Tree) node analyzer that visits different types of nodes in the tree and performs
    analysis on them.

    An AST node analyzer inherits from ast.NodeVisitor of built-in ast module. It overrides the visit methods,
    and implements some validation methods to validate if Function, Class, Arguments, Params and attributes follow
    PEP8 style guide.

    Attributes:
         lineno_to_issues_map (Dict[int, List[str]]): A dictionary that maps line numbers to a list of issue messages
         that occurred in that line. Each line number may have multiple issues associated with it.
    """

    def __init__(self) -> None:
        """
        Initializes the ASTNodeAnalyzer object.

        This method initializes the `lineno_to_issues_map` attribute as an empty dictionary.
        """
        self.lineno_to_issues_map = {}  # Line index: [msg1, msg2, msg5]

    def visit_ClassDef(self, node: ClassDef) -> None:
        """
        Visits a ClassDef node in AST and performs analysis.

        Visits a ClassDef node in AST and checks if names of classes follow CamelCase style naming.
        After checking and adding issue msg to the list, calls generic_visit method to visit and perform the analysis
        on all child nodes of the node.

        Args:
            node : The instance of ClassDef node to analyze.
        """
        self.add_issue_to_list(node.lineno,
                               self.invalid_classname(node.name))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: FunctionDef) -> None:
        """
        Visits a FunctionDef node in AST and performs analysis.

        Visits a FunctionDef node in AST and checks if names of classes follow snake_case style naming.
        After checking and adding issue msg to the list, calls generic_visit method to visit and perform the analysis
        on all child nodes of the node.

        Args:
            node : The instance of FunctionDef node to analyze.
        """
        # analyze function names
        self.add_issue_to_list(
            node.lineno, self.invalid_function_name(node.name))
        # analyze arguments of function
        for arg in node.args.args:
            self.add_issue_to_list(node.lineno,
                                   self.invalid_arg_var_names(arg_name=arg.arg))
        # analyzing body of the function
        for func_child_node in ast.walk(node):
            if isinstance(func_child_node, ast.Name) and isinstance(func_child_node.ctx, ast.Store):
                self.add_issue_to_list(
                    func_child_node.lineno,
                    self.invalid_arg_var_names(
                        var_name=func_child_node.id)
                )
        # analyze default types
        self.add_issue_to_list(
            node.lineno, self.is_mutable(node.args.defaults))

        self.generic_visit(node)

    def print_issues(self) -> None:
        """
        Prints all the line issues stored in the `lineno_to_issues_map`.

        This method iterates over each line index in the `lineno_to_issues_map` and prints the associated issue messages
        for that line.
        """
        for line_index, msgs in self.lineno_to_issues_map.items():
            for msg in msgs:
                print(f'Line {line_index}: {msg}')

    def get_line_issues(self, line_index: int) -> Optional[List[str]]:
        """
        Retrieves the list of issue messages for a specific line index.

        Args:
            line_index (): The line index for which to retrieve the list of issues

        Returns:
            The list of issues occurred in the line index if any. If no issues msgs occurred returns None.
        """
        return self.lineno_to_issues_map.get(line_index, None)

    def get_line_issues_map(self) -> Dict:
        """
        Retrieves the entire `lineno_to_issues_map` dictionary.

        Returns:
            The 'lineno_to_issues_map' dictionary.
        """
        return self.lineno_to_issues_map

    def add_issue_to_list(self, lineno: int, issue: Optional[str]) -> None:
        """
        Adds an issue message to the list of issues for a specific line index.

        If the issue message is not None, it is appended to the list of issues associated with the given line index.
        If the line index is not present in the `lineno_to_issues_map`, a new entry is created.

        Args:
            lineno (): The line index to associate the issue message with.
            issue (): The issue message to add. If None no issue occurred.

        Returns:

        """
        if issue:
            self.lineno_to_issues_map.setdefault(lineno, []).append(issue)

    @staticmethod
    def invalid_arg_var_names(arg_name=None, var_name=None) -> Optional[str]:
        """
        Checks if argument name or variable name follows snake_case style.

        Checks if argument name or variable name follows snake_case style. Checks or argument or variable name
        depends on which one is provided (default - None).
        Although it follows the same styling rule it returns different issue message.

        Args:
            arg_name: The name of the argument to check. Default - None.
            var_name: The name of the variable to check. Default - None.

        Returns:

        """
        if arg_name and not ASTNodeAnalyzer.is_snakecase(arg_name):
            return f"S010 Argument name {arg_name} should be snake_case"
        if var_name and not ASTNodeAnalyzer.is_snakecase(var_name):
            return f"S011 Variable {var_name} should be snake_case"

    @staticmethod
    def is_mutable(items: List[expr]) -> Optional[str]:
        """
        Checks if any default argument for function/method is of a mutable type.

        Args:
            items: The collection of default arguments to check.

        Returns:
            An issue message if any of the arguments is of a mutable type, otherwise None.
        """
        for item in items:
            if any([isinstance(item, ast.Dict), isinstance(item, ast.List), isinstance(item, ast.Set)]):
                return f"S012 The default argument value is mutable"

    @staticmethod
    def is_camelcase(name: str) -> bool:
        """
        Checks if a name follows the CamelCase convention.

        Args:
            name: The name to check.

        Returns:
            True if the name follows the CamelCase convention, False otherwise.
        """
        return True if re.match(r'^([A-Z]+[a-z]*)+', name) else False

    @staticmethod
    def is_snakecase(name: str) -> bool:
        """
        Checks if a name follows the snake_case convention.

        Args:
            name: The name to check.

        Returns:
            True if the name follows the snake_case convention, False otherwise.
        """
        return True if re.match(r'^[a-z_]+[\da-z_]*', name) else False

    @staticmethod
    def invalid_classname(classname: str) -> Optional[str]:
        """
        Checks if class name is invalid - does not follow CamelCase style.

        Args:
            classname: The name of a class.

        Returns:
            An issue message if the class name is invalid, otherwise None.
        """
        if not ASTNodeAnalyzer.is_camelcase(classname):
            return f"S008 Class name {classname} should use CamelCase"

    @staticmethod
    def invalid_function_name(function_name: str) -> Optional[str]:
        """
        Checks if function name is invalid - does not follow snake_case style.

        Args:
            function_name: The name of a class.

        Returns:
            An issue message if the function name is invalid, otherwise None.
        """
        if not ASTNodeAnalyzer.is_snakecase(function_name):
            return f"S009 Function name {function_name} should use snake_case"


class FileStaticCodeAnalyzer:
    """
        Class for analyzing static code issues in a .py file.

        Attributes:
             path: The string path to the file.
             line_index: The current index of line being analyzed.
             blank_lines_before: The number of blank lines before current line.
             ast_analyzer: An instance of ASTNodeAnalyzer for analyzing Abstract Tree Syntax nodes.
        """

    def __init__(self, _path: str) -> None:
        """
        Initialize the FileStaticCodeAnalyzer instance.

        Args:
            _path: The path to the file to be analyzed.
        """
        self.path = _path
        self.line_index = 1
        self.blank_lines_before = 0
        self.ast_analyzer = ASTNodeAnalyzer()

    def __enter__(self):
        """
        Context manager entry point for opening and analyzing the file.

        Returns:
            FileStaticCodeAnalyzer: The FileStaticCodeAnalyzer instance.
        """
        self.file = open(self.path, 'r')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit point for closing the file and performing cleanup.

        Args:
            exc_type: The exception type, if an exception occurred.
            exc_val: The exception value, if an exception occurred.
            exc_tb: The traceback object, if an exception occurred.

        Returns:
            bool: False to indicate that any exceptions should propagate.
        """
        self.file.close()
        # Perform cleanup or resource release
        return False

    def log_issues(self, issues: List[str]) -> None:
        """
        Prints the list of issues messages that occurred in the analyzed line.

        Prints the list of issues that occurred in the analyzed line in the template:
        path/of/analyzed/file.py: Line 1: S001 Issue 1
        path/of/analyzed/file.py: Line 1: S002 Issue 2

        Args:
            issues: List of issues messages that occurred in the analyzed line.
        """
        msg_template = f"{self.path}: Line {self.line_index}: %msg%"
        for issue in issues:
            print(msg_template.replace('%msg%', f'{issue}'))

    def analyze_file(self) -> None:
        """
        Handles the logic of analyzing the file. Creates AST tree, reads through lines of file.

        Creates Abstract Syntax Tree of analyzed file and calls the AST analyzer to visit the tree for the issues.
        Resets the file position to 0 to loop through the lines of the file to pass the for further analysis.
        """
        tree = ast.parse(self.file.read())
        self.ast_analyzer.visit(tree)
        self.file.seek(0)
        for line in self.file:
            line = line.rstrip('\n')
            self.line_analyze_handler(line)
            self.line_index += 1

    def line_analyze_handler(self, line: str) -> None:
        """
        Handles the logic of analyzing the line of the file, and passes the list of issues to print.

        Creates an instance of the Line class, retrieves the list of issues of the line and prints them to the console.
        Retrieves the list of issues that occurred in this line while analyzing the AST.
        Increases the blank lines counter if encounters a blank line, and resets it to 0 if otherwise.

        Args:
            line: The line of the analyzed file.
        """
        if line:
            line_obj = Line(line, self.line_index, self.blank_lines_before)
            line_issues = line_obj.get_issues()
            self.log_issues(line_issues)
            ast_issues = self.ast_analyzer.get_line_issues(self.line_index)
            if ast_issues is not None:
                self.log_issues(ast_issues)
            self.blank_lines_before = 0

        else:
            # if the line is blank skips the analysis and updates blank lines count
            self.blank_lines_before += 1


def get_path_from_console() -> str:
    """
    Parses the path argument from the console call.

    Returns:
        A string representing path.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str)
    args = parser.parse_args()
    return args.path


def get_py_paths(_path: str) -> Generator[pathlib.Path, None, None]:
    """
    Yields the path to all the .py extension files in the given path.

    Yields all the .py files. If the path points to .py yields only the file.
    If the path points to a directory yields paths to all .py files that exist in the directory and all subdirectories.

    Args:
        _path: A string representing a path to file/directory.

    Returns:
        A generator with all paths of .py files.
    """
    path_obj = pathlib.Path(_path)
    if path_obj.is_file():
        yield path_obj
    else:
        yield from path_obj.rglob('*.py')


if __name__ == '__main__':

    user_path = get_path_from_console()

    for path in get_py_paths(user_path):
        path_str = str(path)

        with FileStaticCodeAnalyzer(path_str) as analyzer:
            analyzer.analyze_file()
