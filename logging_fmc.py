import logging
import gzip
from os import rename, remove
from utilites import create_file_path
from logging.handlers import TimedRotatingFileHandler


class LogCollector:
    def __init__(self, log_all=False):
        fName = create_file_path("logs", "firepyower.log")

        if not log_all:
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logging.getLogger()

        conHandler = logging.StreamHandler()
        fileHandler = TimedRotatingFileHandler(
            filename=fName, when="midnight", backupCount=90, interval=1
        )

        conHandler.setLevel(logging.WARN)
        fileHandler.setLevel(logging.INFO)

        logformatCon = logging.Formatter(
            "%(asctime)s %(levelname)s %(message)s", datefmt="%d-%b-%y %H:%M:%S"
        )
        logformatfile = logging.Formatter(
            "%(asctime)s %(name)s %(levelname)s %(message)s",
            datefmt="%d-%b-%y %H:%M:%S",
        )
        conHandler.setFormatter(logformatCon)
        fileHandler.setFormatter(logformatfile)

        fileHandler.rotator = GZipRotator()

        self.logger.addHandler(conHandler)
        self.logger.addHandler(fileHandler)

        self.logger.setLevel(logging.DEBUG)


class GZipRotator:
    def __call__(self, source, dest):
        rename(source, dest)
        f_in = open(dest, "rb")
        f_out = gzip.open("{}.gz".format(dest), "wb")
        f_out.writelines(f_in)
        f_out.close()
        f_in.close()
        remove(dest)
