# pythonspot.com
import os,sys
from flask import Flask, render_template, flash, request, json
from wtforms import Form, TextField, TextAreaField, validators, StringField, SubmitField
 
# App config.
DEBUG = True
app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'
 
class ReusableForm(Form):
    nodes = TextField('Nodes:', validators=[validators.required()])
    port = TextField('Port:', validators=[validators.required()])
    email = TextField('Email:', validators=[validators.required(), validators.Length(min=6, max=35)])
    movie = TextField('Choose a Movie:', validators=[validators.required()])
    genre = TextField('Choose a Genre:', validators=[validators.required()])
    animal = TextField('Choose an Animal:', validators=[validators.required()])
    city = TextField('Choose a City:', validators=[validators.required()])
    neigh0 = TextField('Neighbor 1:', validators=[validators.required()])
    neigh1 = TextField('Neighbor 2:', validators=[])
    neigh2 = TextField('Neighbor 3:', validators=[])
    neigh3 = TextField('Neighbor 4:', validators=[])
    neigh4 = TextField('Neighbor 5:', validators=[])
 

fmt="""
{
    "num_of_nodes":%d,
    "port":%d,
    "email":"%s",
    "p0":%d,
    "p1":%d,
    "p2":%d,
    "p3":%d,
    "neighbors":
    [
        %s
    ]
}
"""

neighborLineFmt = """
    {"ip":"%s", "port":%d},
"""

thcInputFileFmt = "config_%d.json"
thcOutputFileFmt = "output_%d.json"


def createThcInput(numOfNodes, port, email, movie, genre, animal, city, neighbors):
    print "creating input"
    neighborsString = ""

    if len(neighbors) < 1:
        print ("neighbors len is %d" % len(neighbors))
        return False

    for neighbor in neighbors:
        print neighbor[0]
        print neighbor[1]
        neighborsString += ( neighborLineFmt % (str(neighbor[0]), int(neighbor[1])) )

    
    neighborsString = neighborsString[:len(neighborsString)-2] #remove the last ,
    print neighborsString

    thcInputFileName = (thcInputFileFmt % int(port))

    f = open(thcInputFileName, 'w')
    print numOfNodes, " ",port, " ",email, " ",movie, " ",genre, " ",animal, " ",city, " ",neighborsString
    f.write(fmt % (int(numOfNodes), int(port), email, int(movie), int(genre), int(animal), int(city), neighborsString))

    return True
 
@app.route("/", methods=['GET', 'POST'])
def hello():
    form = ReusableForm(request.form)
 
    print form.errors
    if request.method == 'POST':
        
        nodes=request.form['nodes']
        port=request.form['port']
        email=request.form['email']        
        movie=request.form['movie']
        genre=request.form['genre']
        animal=request.form['animal']
        city=request.form['city']

        neighbors = []
        for i in range(0,5):
            splitResult = request.form['neigh' + str(i)].split(":")
            if len(splitResult) == 2:            
                neighbors.append(tuple((splitResult[0],splitResult[1])))

        print nodes, " ", port, " ",email, " ", movie , " ", genre, " ", animal, " ", city
        print neighbors
 
        if form.validate() and createThcInput(nodes, port, email, movie, genre, animal, city, neighbors):
            # Save the comment here.
            flash('Running THC... ')

            thcInputFileName = (thcInputFileFmt % int(port))
            thcOutputFileName = (thcOutputFileFmt % int(port))

            os.system(("./app %s %s" % (thcInputFileName, thcOutputFileName)))           

            output = json.load(open(thcOutputFileName))

            if None == output["match"] or len(output["match"]) == 0:
                flash('No matches found...')
            else:
                match = ("Your match is: %s" % output["match"])
                path = "The path to your match is: "
                for element in output["path"]:
                    path += (element["email"] + ", ")
                    
                flash(match + "\n" + path)              
        else:
            flash('Error: All the form fields are required.')
 
    return render_template('hello.html', form=form)
 
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: gui.py <port_number>"
        exit()
        
    app.run(host='127.0.0.1', port=int(sys.argv[1]))
