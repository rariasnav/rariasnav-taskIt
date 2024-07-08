import React, {useContext, useEffect, useState} from "react";
import { Context } from "../store/appContext";
import { useNavigate, Navigate } from "react-router-dom";
import "../../styles/home.css";
import defaultProfilePicture from "../../../../docs/assets/defaultProfilePicture.jpg"

export const EditMyProfile = () => {
    const {store, actions} = useContext(Context)
    const navigate = useNavigate()
    const [subcategory, setSubcategory] = useState([])
    const [showingProfilePicture, setShowingProfilePicture] = useState(null)
    const [profilePicture, setProfilePicture] = useState(null)
    const [preview, setPreview] = useState(null);
    const [user, setUser] = useState({
        "full_name": "",
        "date_of_birth": "",
        "address":"",
        "profile_resume": "",
        "knowledge": []
    })  

    const handleChange = (e) =>{
        setUser({
            ...user, [e.target.name]: e.target.value
        })        
    }

    const handleSubCategoryChange = (event) => {
        // Obtener los valores seleccionados del evento
        const options = event.target.options;
        const selectedValues = [];
        for (let i = 0; i < options.length; i++) {
          if (options[i].selected) {
            selectedValues.push(options[i].value);
          }
        }
        // Actualizar el estado con los valores seleccionados
        setUser({...user, [event.target.name]: selectedValues});
      };

    const saveInformation = async (e) =>{
        e.preventDefault()
        const result = await actions.updateUserInformation(user)
        if( result === 201){
            navigate('/myProfile')
        }
    }

    const handleImage = async (e) =>{
        const pictureToUpload = e.target.files[0]
        setProfilePicture(pictureToUpload)

        if(pictureToUpload){
            const reader = new FileReader();
            reader.onloadend = () =>{
                setPreview(reader.result)
            }
        reader.readAsDataURL(pictureToUpload)
        } else {
            setPreview(null)
        }
    }

    const handleImageSubmit = async (e) =>{
        e.preventDefault()
        if(!profilePicture){
            alert('Please, select a picture first.')
            return;
        } 

        const formData = new FormData();
        formData.append('profile_picture', profilePicture)

        const result = await actions.updateProfilePicture(formData)
        if(result){
            alert('Profile picture updated');
            document.getElementById("closeProfilePicModalButton").click();
            await actions.getInMyProfile()
        }
    }

    useEffect( ()=> {
        if(store.loggedUser){
            setUser({
                "full_name": store.loggedUser.full_name || "",
                "date_of_birth": store.loggedUser.date_of_birth || "",
                "address": store.loggedUser.address,
                "profile_resume": store.loggedUser.profile_resume || "",
                "knowledge": store.loggedUser.knowledge || []
            }),
            setShowingProfilePicture(store.loggedUser.profile_picture)
        }
    },[store.loggedUser] )

    useEffect( ()=>{
        const getData = async () => {
            const response = await actions.getSubcategories()
            if(response){
                setSubcategory(response)
            }
        } 
        getData()        
    },[])

    return(
        <div className="container background-color">
            {store.loggedUser == false && <Navigate to='/loginRegisterPreview'/>}
            {store.loggedUser &&
            <div className="body m-5">
                <h1 className="primary-text">Profile data</h1>
                    <div className="profile-header-edit text-center mb-4">
                        <div className="profile-picture-edit-container">
                            <img 
                                src={showingProfilePicture || defaultProfilePicture} 
                                className="profile-picture-edit" 
                                alt="Profile"
                            />
                            <button 
                                type="button" 
                                className="btn btn-light ms-2 edit-picture-btn" 
                                data-bs-toggle="modal" 
                                data-bs-target="#profilePicEditModal"
                                >
                                <i className="fa-solid fa-gear"></i>
                            </button>
                        </div>                        
                    </div>
                    <form>
                    <div className="mb-3">
                        <label htmlFor="full_name" className="form-label">Full name</label>
                        <input type="text" className="form-control" aria-describedby="emailHelp" name="full_name" 
                            value={user.full_name} onChange={handleChange}/>   
                            <div className="row">
                                <div className="col-6">
                                    <label htmlFor="date_of_birth" className="form-label">Date of birth</label>
                                    <input type="date" className="form-control" aria-describedby="emailHelp" name="date_of_birth" 
                                        value={user.date_of_birth} onChange={handleChange}/>   
                                </div>
                                <div className="col-6">                              
                                    <label htmlFor="address" className="form-label">Address</label>
                                    <input type="text" className="form-control" aria-describedby="emailHelp" name="address" 
                                        value={user.address} onChange={handleChange}/> 
                                </div>      
                            </div>                                                       
                        </div>
                        <div className="form-floating">
                            <textarea className="form-control" placeholder="Profile resume" style={{height: "100px"}}
                                name="profile_resume" value={user.profile_resume} onChange={handleChange}></textarea>
                            <label htmlFor="profile_resume">Profile resume</label>
                        </div>
                        {store.loggedUser.role === 'vendor' &&
                            <div className="mb-3">
                                <label htmlFor="knowledge" className="form-label">Tasks you can offer</label>
                                <select className="form-select" aria-label="Default select example" name="knowledge"
                                    onChange={handleSubCategoryChange} value={user.knowledge} multiple>
                                    <option disabled value={''}>Select an option</option>
                                    {subcategory.map( (subcategory, index)=>{
                                        return(
                                            <option key={index} value={subcategory.id}>{subcategory.name}</option> 
                                        )
                                    })}                                             
                                </select>                            
                            </div>
                        }
                                           
                            <button type="submit" className="btn btn-primary-custom" onClick={ (e)=> saveInformation(e) }>Save</button>
                            <button className="btn btn-secondary-custom m-2" onClick={ ()=> navigate('/myProfile') }>Back</button>
                    </form>                
            </div>}

            <div className="modal fade" id="profilePicEditModal" tabIndex="-1" aria-labelledby="profilePicModalLabel" aria-hidden="true">
                <div className="modal-dialog modal-dialog-centered">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h5 className="modal-title" id="profilePicModalLabel">Update Profile Picture</h5>
                            <button 
                                type="button" 
                                className="btn-close" 
                                data-bs-dismiss="modal" 
                                aria-label="Close"
                                id="closeProfilePicModalButton"
                                >
                            </button>
                        </div>
                        <div className="picture-upload-container m-2">
                            <form onSubmit={handleImageSubmit} className="picture-upload-form">
                                <input 
                                    type="file" 
                                    accept="image/*"
                                    className="form-control mb-3"
                                    onChange={handleImage}
                                    name="profile_picture"
                                    />
                                    {preview && (
                                        <div className="preview-container">
                                            <img src={preview} alt="Selected" className="preview-image" />
                                        </div>
                                    )}  
                                    <div className="modal-footer">
                                        <button type="button" className="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                        <button type="submit" className="btn btn-primary">Update</button>
                                    </div>                             
                            </form>
                        </div>                        
                    </div>
                </div>
            </div>
        </div>
    )
}