from factordb.factordb import FactorDB
f=FactorDB(24)
f.connect()
print(f.get_factor_list())