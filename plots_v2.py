import csv


def read_file(filename):
    flow = {}
    with open(filename,'r') as f:
        csvfile = csv.DictReader(f)
        for row in csvfile:
            flow[row['flow_id']] = float(row['packet_count'])

    print("Total flows :", len(flow))
    return flow


def accuracy(ground,mal):
    wr_dec = 0
    crr_dec = 0
    missing = 0
    for i in ground:
        if i not in mal:
            missing +=1
        else:
            if abs(mal[i] - ground[i]) >=1:
                wr_dec +=1
            else:
                crr_dec+=1
    
    print("\nWrongly decoded values: ", wr_dec)
    print("Correctly decoded values: ", crr_dec)
    print("missing values: ", missing)


print("For ground truth...")
ground = read_file('ground.csv')
print("\nFor malicious flows...")
decode = read_file('mal.csv')

accuracy(ground,decode)
