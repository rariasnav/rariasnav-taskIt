import React, { useContext, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Context } from "../store/appContext";
import "../../styles/home.css";
import countries from "../../json/countries.json"

export const SignUp = () => {
    const {actions} = useContext(Context)
    const navigate = useNavigate()
    const [user, setUser] = useState({
        "email": "",
        "password": "",
        "gender": "",
        "nationality": "",
        "role": "",
        "phone_number": ""
    })    

    const saveUSer = async (e) =>{
        e.preventDefault()
        const result = await actions.createUser(user)
        if( result==201 ){
            navigate("/")
        }
    }

    const handleChange = (e) => {
        setUser({
            ...user, [e.target.name] : e.target.value
        })
    }   

    return(
        <div className="container">
            <div className="body text-center m-5">
                <h1>Taskit</h1>
                <form className="m-auto" style={{width: "26rem"}}>
                    <div className="mb-3">
                        <label htmlFor="email" className="form-label">Email address</label>
                        <input type="email" className="form-control" aria-describedby="emailHelp"
                            name="email" value={user.email} onChange={handleChange}/>                        
                    </div>
                    <div className="mb-3">
                        <label htmlFor="password" className="form-label">Password</label>
                        <input type="password" className="form-control" name="password" value={user.password}
                            onChange={handleChange}/>
                    </div>
                    <div className="mb-3">
                        <label htmlFor="phone_number" className="form-label">Phone number</label>
                        <input type="number" className="form-control" name="phone_number" value={user.phone_number}
                            onChange={handleChange}/>
                    </div>
                    <div className="mb-3">
                        <label htmlFor="gender" className="form-label">Gender</label>                     
                        <select className="form-select select-custom" aria-label="Default select example" name="gender"
                            onChange={handleChange} value={user.gender}>
                            <option disabled value={''}>Select your gender</option> 
                                    <option value="male">Male</option>
                                    <option value="female">Female</option>
                                    <option value="non_binary">Non binary</option>                            
                        </select>
                    </div>  
                    <div className="mb-3">
                        <label htmlFor="nationality" className="form-label">Nationality</label>                     
                        <select className="form-select select-custom" aria-label="Default select example" name="nationality"
                            onChange={handleChange} value={user.nationality} >
                            <option disabled value={''}>Select your country</option>  
                            {countries.map( (country, index)=> {
                                return(
                                    <option key={index}>{country.name}</option>
                                )
                            })}   
                        </select>
                    </div>   
                    <div className="mb-3">
                        <label htmlFor="role" className="form-label">What would you like to do?</label>                     
                        <select className="form-select select-custom" aria-label="Default select example" name="role"
                            onChange={handleChange} value={user.role}>
                                <option disabled value={''}>Select an option</option> 
                                <option value="client">Look for services</option>
                                <option value="vendor">Offer my services</option>                           
                        </select>
                    </div>                  
                    <button type="submit" className="btn btn-primary" onClick={ (e)=>saveUSer(e) }>Create account</button>
                </form>
                                
            </div>
        </div>
    )
}