#! /bin/python3

NUM_TESTS=1000

db = open("name_server/db.goertzen", "w")

db.write("$TTL\t604800\n")
db.write("@\t\tIN\t\tSOA\t\tns1.goertzen. hostmaster.goertzen. (\n")
db.write("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t    6\t ; Serial\n");
db.write("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t    604800\t ; Refresh\n");
db.write("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t    86400\t ; Retry\n");
db.write("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t    2419200\t ; Expire\n");
db.write("\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t    604800 )\t ; Negative Cache TTL\n");

db.write("; name servers - NS records\n")
db.write("@\t\tIN\t\tNS\t\tns1.goertzen.\n")
db.write("; name servers - A records\n")
db.write("ns1\t\tIN\t\tA\t\t172.20.0.4\n")
db.write("\n; Burn-in A record\n")
db.write("test.goertzen.\t\tIN\t\tA\t\t42.42.42.42")
db.write("\n\n; Test A records\n")

for i in range(NUM_TESTS):
    db.write("test{}.goertzen.\t\tIN\t\tA\t\t42.42.42.42\n".format(i))

db.close()
