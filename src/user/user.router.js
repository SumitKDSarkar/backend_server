const express=require("express")
const UserModel=require("./user.model")
const app=express.Router()
const jwt=require("jsonwebtoken")
const argon2=require("argon2")

app.post("/signup",async(req,res)=>{
const {username,email,password}=req.body

const hash=await argon2.hash(password)
try{
    const user=new UserModel({username,email,password:hash})
    await user.save()
    return res.status(201).send("User Successfully Created")

}
catch(e){

    console.log(e.message)
    return res.send(e.message)
}

})

// app.post("/signup", async (req, res) => {
//     let {username,email,password} = await req.body;
  
//     try {
//       let user = await UserModel.findOne({ email });
  
//       if (user) {
//         res.status(401).send("Email is already exists");
//       } else {
//             await UserModel.create(req.body);
//         // let token = `${newUser.email}:${newUser.id}:${Math.random() * 10000}`;
  
//         res.send({username});
//       }
//     } catch (e) {
//       res.status(500).send(e.message);
//     }
//   });


app.post("/login",async(req,res)=>{

    const {email,password}=req.body;

    const user=await UserModel.findOne({email});

  console.log(user,password)
  if(user){

    if(user.password==password || await argon2.verify(user.password,password)){

        const token=jwt.sign({id:user._id,username:user.username,email:user.email},"SECRET",{expiresIn:"24 hours"})
        const refreshToken=jwt.sign({id:user._id,username:user.username,email:user.email},"REFRESH",{expiresIn:"7 days"})
        return res.status(201).send({message:"Login Successful",token,refreshToken,user})
    }
    else{

        return res.status(401).send("Invalid Credentials")
    }
  }
  else{
    return res.status(401).send("Invalid Credentials")
}

    
})

app.put("/:id",async(req,res)=>{
    let token=req.headers["authorization"]
    if(token){
        const decoded=jwt.decode(token)

        if(decoded.id==req.params.id){


           
console.log(req.params.id,req.body.creds)
            try{
                const updateUser=await UserModel.findByIdAndUpdate(req.params.id,
                    {
                        $set:req.body.creds,

                    },{new:true})

                res.status(200).send(updateUser)
            }catch(e){
                res.status(401).send("You Can Update Your Account")
            }
        }
    }
})


//Delete function
app.delete("/:id",async(req,res)=>{
    let token=req.headers["authorization"]

if(token){
const decoded=jwt.decode(token)

if(decoded.id===req.params.id ){
    console.log(decoded.id)
try{
    await UserModel.findByIdAndDelete(req.params.id)
    return res.status(200).send("account deleted");

}catch(e){
    return res.send(e.message)
}
}

else{
    return res.status(401).send("you can only delete your account")
}
}
    
})


//Get function
app.get("/:id",async(req,res)=>{
const token=req.headers["authorization"]
if(token){
    const decoded=jwt.decode(token)
    if(decoded.id==req.params.id){

        try{
            const user=await UserModel.findById(req.params.id)
            const {password,...others}=user._doc
            return res.send(others)
        }
        catch(e){
            res.status(500).send(e.message)
        }

    }
}
   
});




module.exports=app;
