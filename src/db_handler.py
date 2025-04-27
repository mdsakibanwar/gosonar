from functools import lru_cache
import sqlite3
from singleton import Singleton
from cons import *
from loguru import logger
from pathlib import Path
import os


class DB_Handler(metaclass=Singleton):
    def __init__(self) -> None:
        self._bypass = False
        self._skipped_stems = []
        self.project_root = project_root = Path(__file__).resolve().parent.parent

    def __doc__(self):
        return f"DB Handler provides an interface to work with the database without having to know the inner structure of it"

    def close(self):
        if self.conn:
            self.conn.close()

    @property
    def skipped_stems(self):
        return self._skipped_stems

    def build_tables(self, db_name):
        self.conn = sqlite3.connect(db_name)
        with open(f'{self.project_root}/src/sql/tables.sql', 'r') as f:
            script = f.read()
        cursor = self.conn.cursor()
        cursor.executescript(script)
        self.conn.commit()
        self.conn.close()

    def setup_db(self, db_name, bypass = False, generate_skipped_stem = True):
        self._bypass = bypass
        if not bypass:
            self.conn = sqlite3.connect(db_name)
            if generate_skipped_stem:
                for skipped in self.get_aborted_stems():
                    stem = skipped[STEM_FIELDS.MAPPING[STEM_FIELDS.STEM]]
                    self._skipped_stems.append(stem)

    def execute_and_commit(self, sql):
        if self._bypass:
            return
        while (True):
            try:
                cursor = self.conn.cursor()
                cursor.execute(sql)
                self.conn.commit()
                break
            except sqlite3.IntegrityError as e:
                break
            except sqlite3.OperationalError as e:
                pass
            except Exception as e:
                logger.exception(e)
                os._exit(1)

    def execute(self, sql):
        if self._bypass:
            return None
        while (True):
            try:
                cursor = self.conn.cursor()
                cursor.execute(sql)
                return cursor
            except sqlite3.OperationalError as e:
                pass
            except Exception as e:
                logger.exception(e)
                os._exit(1)

    # STEM FUNCTIONS

    def add_stem(self, stem):
        sql = f"INSERT INTO stems(stem, status, func_names) VALUES{stem.get_db_row()}"
        self.execute_and_commit(sql)

    def get_stem(self, stem_str):
        sql = f"SELECT * from stems WHERE stem = '{stem_str}'"
        cursor = self.execute(sql)
        if cursor is not None:
            return cursor.fetchone()

    def update_stem_status(self, stem):
        sql = f"UPDATE stems SET status = {stem.status} where stem = '{stem.stem_str}'"
        self.execute_and_commit(sql)
        if stem.status == STEM_STATUS.ABORT:
            self._skipped_stems.append(stem.stem_str)

    def get_aborted_stems(self):
        sql = f"SELECT stem FROM stems WHERE status = {STEM_STATUS.ABORT}"
        cursor = self.execute(sql)
        if cursor is None:
            return []
        return cursor.fetchall()

    # LASSO FUNCTIONS

    def add_lasso(self, lasso):
        sql = f"INSERT INTO lassos VALUES{lasso.get_db_row()}"
        self.execute_and_commit(sql)

    def get_n_lassos_by_status(self, count, status, start):
        sql = f"SELECT * from lassos WHERE status = {status} ORDER BY length(loop), length(stem) LIMIT {count} offset {start}"
        cursor = self.execute(sql)
        if cursor is None:
            return []
        return cursor.fetchmany(size = count)

    def get_all_lasso(self):
        sql = f"SELECT * FROM lassos"
        cursor = self.execute(sql)
        if cursor is not None:
            return cursor.fetchall()
        return []

    def _update_lasso_status(self, status, loop_str, stem_str):
        sql = f"UPDATE lassos SET status = {status} where loop = '{loop_str}' and stem = '{stem_str}'"
        self.execute_and_commit(sql)

    def get_all_targeted_func_in_loop_lasso(self, func):
        sql = f"select t1.* from lassos t1 inner join loops t2 on t1.loop = t2.loop where t2.func_names like '%{func}%'"
        cursor = self.execute(sql)
        if cursor is not None:
            return cursor.fetchall()
        return []

    def update_lasso_status(self, lasso):
        self._update_lasso_status(lasso.status, lasso.loop.loop_str, lasso.stem.stem_str)

    def update_lasso_data(self, lasso):
        sql = f"UPDATE lassos SET data = '{lasso.data_str}' where loop = '{lasso.loop.loop_str}' and stem = '{lasso.stem.stem_str}'"
        self.execute_and_commit(sql)

    def _update_lasso(self, lasso, column, data):
        sql = f"UPDATE lassos SET {column} = {data} WHERE loop = '{lasso.loop.loop_str}' and stem = '{lasso.stem.stem_str}'"
        self.execute_and_commit(sql)

    # LOOP FUNCTIONS

    def add_loop(self, loop):
        sql = f"INSERT INTO loops(loop,func_names) VALUES('{loop.loop_str}', '{loop.func_names}')"
        row = self.get_loop(loop.loop_str)
        if row is None:
            self.execute_and_commit(sql)

    def update_loop_status(self, loop):
        sql = f"UPDATE loops SET status = {loop.status} where loop = '{loop.loop_str}'"
        self.execute_and_commit(sql)

    def get_n_loops_by_status(self, start, count, status):
        cursor = self.execute(f"SELECT * FROM loops WHERE status = {status} ORDER BY ROWID LIMIT {count} offset {start}")
        if cursor is None:
            return []
        return cursor.fetchmany(count)

    def get_loop(self, loop: str):
        """
        Get a loop db row by loop
        Args:
            loop (str): json dumps of a list or loop.loop_str
        """
        cursor = self.execute(f"SELECT * FROM loops WHERE loop = '{loop}'")
        if cursor is not None:
            return cursor.fetchone()
