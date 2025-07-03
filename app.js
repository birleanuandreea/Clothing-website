const sqlite3 = require('sqlite3').verbose();
const cookieParser=require('cookie-parser');
const express = require('express'); 
const expressLayouts = require('express-ejs-layouts'); 
const bodyParser = require('body-parser') 
const session = require('express-session');


const app = express(); 
app.use(cookieParser());

const port = 6789; 



// directorul 'views' va conține fișierele .ejs (html + js executat la server) 
app.set('view engine', 'ejs'); 
// suport pentru layout-uri - implicit fișierul care reprezintă template-ul site-ului 
// este views/layout.ejs 
app.use(expressLayouts); 
// directorul 'public' va conține toate resursele accesibile direct de către client 
// (e.g., fișiere css, javascript, imagini) 
app.use(express.static('public')) 
// corpul mesajului poate fi interpretat ca json; datele de la formular se găsesc în 
// format json în req.body 
app.use(bodyParser.json()); 
// utilizarea unui algoritm de deep parsing care suportă obiecte în obiecte 
app.use(bodyParser.urlencoded({ extended: true })); 
// la accesarea din browser adresei http://localhost:6789/ se va returna textul 'Hello 
// World' 
// proprietățile obiectului Request - req - https://expressjs.com/en/api.html#req 
// proprietățile obiectului Response - res - https://expressjs.com/en/api.html#res 
// app.get('/', (req, res) => res.render('index')); 

// session module
app.use(session({
    secret: 'secret',           // for cookie encription
    resave: false,              // // sesiunea nu va fi salvata din nou daca nu a fost modificata
    saveUninitialized: false    // nu salveaaza sesiuni goale
}));


const blockedIPs = {}; // { 'ip': { count: 0, blockedUntil: timestamp } }
const failedLogins = {}; // { ip: { count, firstAttempt, blockedUntil }, utilizator: { count, firstAttempt, blockedUntil } }


app.use((req, res, next) => {
    const ip = req.ip;

    if (blockedIPs[ip]) {
        const now = Date.now();

        
        if (blockedIPs[ip].blockedUntil && blockedIPs[ip].blockedUntil > now) {
            return res.status(403).send("Acces interzis temporar din cauza accesarilor repetate de resurse inexistente.");
        }

        
        if (blockedIPs[ip].blockedUntil && blockedIPs[ip].blockedUntil <= now) 
        {
            delete blockedIPs[ip];
        }
    }

    next();
});


app.use((req, res, next) => {
    res.locals.utilizator = req.session.utilizator;
    res.locals.cos = req.session.cos;
    res.locals.admin = req.session.admin;
    next();
});




// -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// --------------------------QUIZ-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
const fs = require('fs').promises;
app.get('/chestionar', async(req, res) => { 
    try{
        const data = await fs.readFile('intrebari.json');
        const intrebari = JSON.parse(data);
        res.render('chestionar', {intrebari});
    }catch(err){
        console.error("Eroare la citirea fisierului JSON: ", err);
        res.status(500).send("Eroare");
    }
    });



app.post('/rezultat-chestionar', async(req, res) => {
    try{
        const data = await fs.readFile('intrebari.json');
        const listaIntrebari = JSON.parse(data);
        let punctaj = 0;

        listaIntrebari.forEach((intrebare, index) => {
            const raspuns = parseInt(req.body[`intrebare${index}`]);
            if (raspuns === intrebare.corect) 
            {
                punctaj++;
            }
        });

        res.render('rezultat-chestionar', {
            punctaj,
            total: listaIntrebari.length
        });

    } catch (err) {
        console.error('Eroare la citirea fisierului JSON:', err);
        res.status(500).send('Eroare interna');
    }
});




// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// --------------------Autentificare----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.get('/autentificare', (req, res) => {
    const errMsg = req.cookies.errMsg || '';
    res.clearCookie('errMsg');
    res.render('autentificare', { errMsg });
});


app.post('/verificare-autentificare', async (req, res) => {
    try {

        const { utilizator, parola } = req.body;
        const ip = req.ip;
        const now = Date.now();


        const isBlocked = (entry) =>
            entry?.blockedUntil && entry.blockedUntil > now;


        if (isBlocked(failedLogins[ip]) || isBlocked(failedLogins[utilizator])) 
        {
            res.cookie('errMsg', 'Cont blocat temporar', { maxAge: 5000, httpOnly: false, path: '/autentificare' });
            return res.redirect('/autentificare');
        }


        if (req.session.utilizator) return res.redirect('/autentificare');

        const usersData = JSON.parse(await fs.readFile('utilizatori.json'));
        let user = usersData.find(u => u.utilizator === utilizator && u.parola === parola);

        if (!user) {
            const adminsData = JSON.parse(await fs.readFile('admins.json'));
            user = adminsData.find(u => u.utilizator === utilizator && u.parola === parola);
        }

        if (user) {
            delete failedLogins[ip];
            delete failedLogins[utilizator];

            res.cookie('utilizator', user.utilizator);
            res.clearCookie('errMsg');
            req.session.utilizator = {
                utilizator: user.utilizator,
                nume: user.nume,
                prenume: user.prenume,
                email: user.email,
                telefon: user.telefon,
                data: user.data,
                ora: user.ora,
                varsta: user.varsta
            };

            const adminsData = JSON.parse(await fs.readFile('admins.json'));
            const esteAdmin = adminsData.find(a => a.utilizator === user.utilizator);
            if (esteAdmin) {
                req.session.admin = 1;
            }

            return res.redirect('/');
        }

        // gestionarea autentificarilor esuate
        const registerFail = (key) => {
            if (!failedLogins[key]) 
            {
                failedLogins[key] = { count: 1, firstAttempt: now };
            }
            else 
            {

                failedLogins[key].count += 1;

                    // blocare in functie de nr de incercari
                if (failedLogins[key].count >= 2) 
                {
                    failedLogins[key].blockedUntil = now + 5 * 1000; // blocare 10 secunde
                }
                else if (failedLogins[key].count >= 10)
                {
                    failedLogins[key].blockedUntil = now + 10 * 60 * 1000; // blocare 10 min
                }
                
            }
        };

        registerFail(ip);
        registerFail(utilizator);

        res.cookie('errMsg', 'Nume de utilizator sau parola greșite', { maxAge: 5000, httpOnly: false, path: '/autentificare' });
        res.redirect('/autentificare');

    } catch (err) {
        console.error("Eroare la autentificare:", err);
        res.status(500).send("Eroare interna");
    }
});



app.get('/delogare', (req, res) => {
    res.clearCookie('utilizator');
    req.session.destroy(err => {
        res.redirect('/');
    });
});



// ----------------------------------------------------------------------------------------------------------------------------------------------------------------------
// ---------------------------------------------Baza de date----------------------------------------------------------------------------------------------------------------------
app.get('/creare-bd', (req, res) => {
    const db = new sqlite3.Database('cumparaturi.db');

    db.serialize(() => {
        
        db.run(`CREATE TABLE IF NOT EXISTS produse (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nume TEXT NOT NULL,
            descriere TEXT,
            pret REAL NOT NULL
        )`, (err) => {
            if (err) {
                console.error("Eroare la crearea tabelei:", err);
                db.close();
                return res.status(500).send("Eroare la crearea bazei de date");
            }
            
            console.log("Tabela 'produse' exista deja sau a fost creata cu succes");
            db.close();
            res.redirect('/');
        });
    });
});


app.get('/incarcare-bd', (req, res) => {
    const db = new sqlite3.Database('cumparaturi.db');

    db.serialize(() => {
        db.get("SELECT COUNT(*) AS count FROM produse", (err, row) => {
            if (err) {
                console.error("Eroare la verificarea produselor:", err);
                db.close();
                return res.status(500).send("Eroare la verificare");
            }

            if (row.count > 0) 
            {
                console.log("Produsele exista deja in tabela");
                db.close();
                return res.redirect('/');
            }

            const stmt = db.prepare("INSERT INTO produse (nume, descriere, pret) VALUES (?, ?, ?)");

            stmt.run("Rochie", "Rochie elegantă de vară cu imprimeu floral", 199.99);
            stmt.run("Tricou", "Tricou casual din bumbac organic", 59.99);
            stmt.run("Pantaloni", "Pantaloni slim fit din denim premium", 149.99);
            stmt.run("Bluză", "Bluză ușoară cu mânecă lungă", 89.99);
            stmt.run("Geacă", "Geacă de primăvară impermeabilă", 249.99);

            stmt.finalize((err) => {
                if (err) {
                    console.error("Eroare la inserarea produselor:", err);
                    db.close();
                    return res.status(500).send("Eroare la inserarea produselor");
                }

                console.log("Produsele au fost inserate cu succes!");
                db.close();
                res.redirect('/');
            });
        });
    });
});



app.get('/', (req, res) => {
    const db = new sqlite3.Database('cumparaturi.db');
    
    db.all("SELECT * FROM produse", (err, produse) => {
        if (err) {
            console.error("Eroare la citirea produselor:", err);
            db.close();
            return res.render('index', { 
                produse: [],
                cos: req.session.cos || []
            });
        }
        
        db.close();
        res.render('index', { 
            produse: produse,
            cos: req.session.cos || []
        });
    });
});



app.get('/adaugare_cos', (req, res) => {
    
    const productId = req.query.id;
    
    
    if (!req.session.utilizator) {
        req.session.cos = [];
        return res.redirect('/autentificare');
    }
  
    if (!req.session.cos) {
        req.session.cos = [];
    }
    

    req.session.cos.push(productId);
    

    res.redirect('/');
});




app.get('/vizualizare-cos', (req, res) => {

    if (!req.session.utilizator) {
        
        return res.redirect('/autentificare');
    }
    

    if (!req.session.cos || req.session.cos.length === 0) {
        return res.render('vizualizare-cos', { 
            produse: [],
            total: 0
        });
    }
    
  
    const db = new sqlite3.Database('cumparaturi.db');
    const placeholders = req.session.cos.map(() => '?').join(',');
    
    db.all(`SELECT * FROM produse WHERE id IN (${placeholders})`, req.session.cos, (err, produse) => {
        if (err) {
            console.error("Eroare la citirea produselor din cos:", err);
            db.close();
            return res.status(500).send("Eroare la citirea produselor din cos");
        }
        
    const frecventa = {};
    req.session.cos.forEach(id => {
        frecventa[id] = (frecventa[id] || 0) + 1;
    });


    let total = 0;
    const produseCuCantitate = produse.map(produs => {
                const cantitate = frecventa[produs.id] || 1;
                total += produs.pret * cantitate;
                return {
                        id: produs.id,
                        nume: produs.nume,
                        pret: produs.pret,
                        descriere: produs.descriere,
                        cantitate: cantitate
                    };
    });

    db.close();
    res.render('vizualizare-cos', { 
        produse: produseCuCantitate,
        total: total
    });

    });
});




// --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----Admin------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.get('/admin', (req, res) => {
    
    if (!req.session.admin) 
    {
        return res.status(403).send('Acces interzis');
    }
    res.render('admin');
});

app.post('/admin', (req, res) => {
    if (!req.session.admin) 
    {
        return res.status(403).send('Acces interzis');
    }

    const { nume, descriere, pret } = req.body;

    const numeValid = /^[A-Z][a-zA-Z\s]*$/.test(nume);
    const pretValid = /^\d+(\.\d{2})$/.test(pret);
    const descriereValida = /^[a-zA-Z0-9\s.,!?'"]+$/.test(descriere); //alfanumerice, spatii si cateva semne de punctuatie


    if (!numeValid || !pretValid || !descriereValida) 
    {
        return res.redirect('/admin');
    }

    const db = new sqlite3.Database('cumparaturi.db');

    db.run(
        `INSERT INTO produse (nume, descriere, pret) VALUES (?, ?, ?)`,
        [nume, descriere, parseFloat(pret)],
        function(err) {
            db.close();

            if (err) {
                console.error('Eroare la inserarea produsului:', err);
                return res.status(500).send('Eroare la inserare');
            }

            console.log(`Produs adaugat cu ID: ${this.lastID}`);
            res.redirect('/');
        }
    );
});





// -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
// ----------------------------------Resurse inexistente--------------------------------------------------------------------------------------------------------------------------------------------------------------------------
app.use((req, res, next) => {
    const ignoredRoutes = ['/.well-known/appspecific/com.chrome.devtools.json'];
    const ip = req.ip;
    const now = Date.now();
    if (ignoredRoutes.includes(req.path)) {
        return next();
    }

    if (!blockedIPs[ip]) 
    {
        blockedIPs[ip] = { count: 1, firstAttempt: now };
    } 
    else 
    {
        blockedIPs[ip].count += 1;

        if (blockedIPs[ip].count >= 3) 
        {
            blockedIPs[ip].blockedUntil = now + 5 * 1000; // blocare 20 secunde
        }
    }

    console.warn(`Resursa inexistenta accesata de ${ip}: ${req.originalUrl}`);
    res.status(404).send("Resursa cautata nu exista.");
});
app.listen(port, () => console.log(`Serverul rulează la adresa http://localhost: :${port}/`)); 
