import csv


def ground_file(filename):
    ground = {}
    with open(filename,'r') as f:
        csvfile = csv.reader(f)
        for lines in csvfile:
            ground[lines[0]] = float(lines[1])

    print("ground vales :", len(ground))
    return ground


def accuracy(ground,mal_filename):
    mal = {}
    with open(mal_filename,'r') as f:
        csvfile = csv.reader(f)
        for lines in csvfile:
            mal[lines[0]] = float(lines[1])
            if mal[lines[0]] <0:
                mal[lines[0]] = 0
    
    wr_dec = 0
    crr_dec = 0
    missing = 0
    x = []
    for i in ground:
        if i not in mal:
            missing +=1
        else:
            if abs(mal[i] - ground[i]) >=1:
                wr_dec +=1
                x.append(abs(mal[i]-ground[i]))
            else:
                crr_dec+=1
    x.sort()
    print(x)
    print("total decoded values: ", len(mal))
    print("Wrongly decoded values: ", wr_dec)
    print("Correctly decoded values: ", crr_dec)
    print("missing values: ", missing)



ground = ground_file('ground.csv')

print("\nunique error:")
accuracy(ground,'unique.csv')
try:
    print("\nNormal error:")
    accuracy(ground,'normal.csv')

    print("\nRelay error:")
    accuracy(ground,'relay.csv')

    print("\nrelay with random error:")
    accuracy(ground,'random.csv')
except:
    print("done")

