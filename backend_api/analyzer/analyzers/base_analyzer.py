class BaseAnalyzer:
    """
    Base class for all file analyzers.
    Your custom analyzer should inherit from this class.
    """
    # A unique name for the analyzer.
    name = "base"

    def can_analyze(self, data, magic_bytes_info):
        """
        Determines if this analyzer can handle the given file data.

        :param data: The raw file data (bytes).
        :param magic_bytes_info: A dictionary containing the 'magic_bytes_type' and 'mime_type'.
        :return: True if the analyzer can handle the file, False otherwise.
        """
        return False

    def analyze(self, file_storage, data, findings):
        """
        Performs the analysis on the file.

        :param file_storage: The file storage object from Flask.
        :param data: The raw file data (bytes).
        :param findings: A list to which analysis findings should be appended.
        :return: A dictionary representing the file structure, or None.
        """
        raise NotImplementedError("Each analyzer must implement the 'analyze' method.")
