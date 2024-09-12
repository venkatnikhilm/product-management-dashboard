import express from 'express';
import { DynamoDBClient, ListTablesCommand } from '@aws-sdk/client-dynamodb';  // Low-level client
import { DynamoDBDocumentClient, PutCommand, ScanCommand, GetCommand, UpdateCommand, DeleteCommand } from '@aws-sdk/lib-dynamodb';  // Document Client
import dotenv from 'dotenv';
import { v4 as uuidv4 } from 'uuid'; 
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import redis from 'redis';

const redisClient = redis.createClient({
     url: 'redis://127.0.0.1:6379'
});
redisClient.connect()
    .then(()=>{
        console.log('Redis connected');
    })
    .catch(err =>{
        console.error('Redis connection error:', err);
    })
redisClient.on('error',(err)=>{
    console.error('Redis error:', err);
})
 
dotenv.config();

const app = express();
app.use(express.json());

// Initialize low-level DynamoDB client
const client = new DynamoDBClient({
    region: 'us-east-1',  // Use your DynamoDB region
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
});



// Initialize the higher-level Document Client
const dynamodb = DynamoDBDocumentClient.from(client);


const TABLE_NAME = 'Products';
//Check if server is running
app.get('/', (req,res) => {
    res.send('Server is running');
});

//Start the server
const PORT = process.env.PORT || 5001;
app.listen(PORT, ()=>{
    console.log(`Server is running on port ${PORT}`);
}) 

// Test DynamoDB connection: List all tables
app.get('/test-dynamodb', async (req, res) => {
    try {
        const data = await client.send(new ListTablesCommand({}));
        res.send(`Server is running. Tables: ${data.TableNames.join(', ')}`);
    } catch (err) {
        console.error('DynamoDB connection error:', err);
        res.status(500).send('DynamoDB connection error');
    }
});

// Create a new product
//Made this a protected route with the verifyToken middleware
app.post('/products',verifyToken, async (req, res) => {
    const { name, price, category } = req.body;
    const productID = uuidv4();  // Generate a unique ProductID

    const params = {
        TableName: TABLE_NAME,
        Item: {
            ProductID: productID,
            Name: name,
            Price: price,
            Category: category
        }
    };

    try {
        // Use PutCommand to add a product
        await dynamodb.send(new PutCommand(params));
        res.status(201).json({ message: 'Product created successfully', ProductID: productID });
    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({ error: 'Could not create product' });
    }
});

// Get all products
app.get('/products', async (req, res) => {
    const params = {
        TableName: TABLE_NAME
    };

    try {
        // Use ScanCommand to get all products
        const data = await dynamodb.send(new ScanCommand(params));
        res.status(200).json(data.Items);  // Return the list of products
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ error: 'Could not fetch products' });
    }
});

// Get a product by ID with Redis caching
app.get('/products/:id', async (req, res) => {
    const productID = req.params.id; 
    try {
        const cachedProduct = await redisClient.get(productID);
        if (cachedProduct) {
            console.log("Cache hit");
            return res.status(200).json(JSON.parse(cachedProduct));
        }

        // If not found in cache, fetch from DynamoDB
        const params = {
            TableName: TABLE_NAME,
            Key: { ProductID: productID }
        };

        const data = await dynamodb.send(new GetCommand(params));
        if (data.Item) {
            await redisClient.setEx(productID, 3600, JSON.stringify(data.Item));  // Cache result for 1 hour
            return res.status(200).json(data.Item);
        } else {
            return res.status(404).json({ error: 'Product not found' });
        }
    } catch (error) {
        console.error('Error fetching product:', error);
        return res.status(500).json({ error: 'Could not fetch product' });
    }
});


// Update a product by ID
//Made this a protected route with the verifyToken middleware
app.put('/products/:id',verifyToken, async (req, res) => {
    const productID = req.params.id;
    const { name, price, category } = req.body;

    const params = {
        TableName: TABLE_NAME,
        Key: { ProductID: productID },
        UpdateExpression: 'set #n = :name, Price = :price, Category = :category',
        ExpressionAttributeNames: { '#n': 'Name' },  // Avoid reserved words
        ExpressionAttributeValues: {
            ':name': name,
            ':price': price,
            ':category': category
        },
        ReturnValues: 'UPDATED_NEW'
    };

    try {
        // Use UpdateCommand to update a product
        const data = await dynamodb.send(new UpdateCommand(params));
        res.status(200).json(data.Attributes);
    } catch (error) {
        console.error('Error updating product:', error);
        res.status(500).json({ error: 'Could not update product' });
    }
});

// Delete a product by ID
//Made this a protected route with the verifyToken middleware
app.delete('/products/:id',verifyToken, async (req, res) => {
    const productID = req.params.id;

    const params = {
        TableName: TABLE_NAME,
        Key: { ProductID: productID }
    };

    try {
        // Use DeleteCommand to delete a product
        await dynamodb.send(new DeleteCommand(params));
        res.status(200).json({ message: 'Product deleted successfully' });
    } catch (error) {
        console.error('Error deleting product:', error);
        res.status(500).json({ error: 'Could not delete product' });
    }
});

const users = [
    {
    id: '1',
    username: 'testuser',
    password: bcrypt.hashSync('testpassword', 8)
}
];
const JWT_SECRET = process.env.JWT_SECRET

app.post('/login', async(req, res) => {
    const {username, password} =req.body;
    //Find the user
    const user = users.find(u => u.username === username);
    if (!user){
        return res.status(404).json({message: 'User not found'})
    }
    //Check the password
    const isPasswordValid = bcrypt.compareSync(password, user.password);
    if (!isPasswordValid){
        return res.status(401).json({message: 'Invalid password'})
    }

    //Generate a JWT token
    const token = jwt.sign({id:user.id}, JWT_SECRET, {expiresIn: '1h'})
    res.status(200).json({message: "Login successfuk", token});
});

//JWT middleware to protect routes
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(403).json({ message: 'No token provided' });
    }

    // Check if the token starts with 'Bearer ' and split the token
    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        return res.status(403).json({ message: 'Token format invalid' });
    }

    const token = parts[1];  // Extract the token after 'Bearer'
    console.log("Token extracted:", token);

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            console.error('JWT verification failed:', err);
            return res.status(401).json({ message: 'Unauthorized: Invalid token' });
        }
        req.userId = decoded.id;
        next();
    });
}
