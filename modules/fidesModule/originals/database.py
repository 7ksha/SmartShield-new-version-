# This file is truncated file from original smartshield repository - only methods that are necessary for module to build
# were left
# https://github.com/stratosphereips/StratosphereLinuxIPS/blob/5015990188f21176224e093976f80311524efe4e/smartshield_files/core/database.py
# --------------------------------------------------------------------------------------------------
from redis.client import Redis


class Database(object):
    """ Database object management """

    def __init__(self):
        self.r: Redis

    def start(self, smartshield_conf):
        raise NotImplemented('Use real implementation for smartshield!')


__database__ = Database()
