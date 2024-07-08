import React, { useContext, useEffect, useState } from "react";
import { Context } from "../store/appContext";
import { useNavigate, Navigate } from "react-router-dom";
import "../../styles/home.css";
import defaultProfilePicture from "../../../../docs/assets/defaultProfilePicture.jpg"
import { act } from "react-dom/test-utils";

export const GetInMyProfile = () =>{
    const {store, actions} = useContext(Context)
    const navigate = useNavigate()
    const [offerKnowledge, setOfferKnowledge] = useState([])
    const [userKnowledge, setUserKnowledge] = useState([])
    const [getGallery, setGetGallery] = useState([])
    const [userGallery, setUserGallery] = useState([])
    const [showPictureUpload, setShowPictureUpload] = useState(false);
    const [galleryPicturePreview, setGalleryPicturePreview] = useState(null)
    const [galleryPicture, setGalleryPicture] = useState(null)

    const getUserKnowledge = (email, role) => {
        if(role == 'vendor'){
            return offerKnowledge.filter(offerKnown => offerKnown.user.email === email);
        }
    };

    const galleryImages = [
        "https://picsum.photos/200/300",
        "https://picsum.photos/200/300?grayscale",
        "https://picsum.photos/200/300/?blur",
        "https://picsum.photos/seed/picsum/200/300",
        "https://picsum.photos/200/300?random=1",
        "https://picsum.photos/200/300?random=2",
        "https://picsum.photos/200/300?random=1",
        "https://picsum.photos/200/300?random=2",
    ];

    const handleImage = async (e)=>{
        const pictureToUpload = e.target.files[0]
        setGalleryPicture(pictureToUpload)

        if(pictureToUpload){
            const reader = new FileReader()
            reader.onloadend = () =>{
                setGalleryPicturePreview(reader.result)
            }
        reader.readAsDataURL(pictureToUpload)
        } else {
            setGalleryPicturePreview(null)
        }
    }

    const handleImageSubmit = async (e) =>{
        e.preventDefault()
        if(!galleryPicture){
            alert('Please, select a picture first.')
            return;
        }

        const formData = new FormData()
        formData.append('gallery_picture', galleryPicture)

        const result = await actions.uploadGalleryPicture(formData)
        if(result){
            alert('Picture uploaded.')
        }
    }

    useEffect( ()=>{
        const getData = async () =>{
            const response = await actions.getOfferKnowedle()
            if(response){
                setOfferKnowledge(response)
            }
        }
        getData()
    },[actions])

    useEffect( ()=>{
        const getData = async() => {
            if(store.loggedUser && store.loggedUser.email){
                const knowledge = getUserKnowledge(store.loggedUser.email, store.loggedUser.role)
                setUserKnowledge(knowledge)
            }
        }
        getData()   
    },[store.offerKnowledge, store.loggedUser, offerKnowledge])

    useEffect( ()=>{
        const getData = async ()=>{
            const response = await actions.getGalleryPictures()
            if(response){
                setGetGallery(response)
            }

        };
        getData()
    },[])
    
    useEffect( ()=>{
        if(store.loggedUser && getGallery.length > 0){
            setUserGallery(getGallery.filter( (gallery)=> gallery.user.email === store.loggedUser.email))
        }        
    },[store.loggedUser, getGallery])    

    return(
        <div className="container my-5">
            {store.loggedUser == false && <Navigate to='/loginRegisterPreview'/>}  
            {store.loggedUser && 
            <div className="profile-body">
                <div className="profile-header text-center mb-4">
                    <img 
                        src={store.loggedUser.profile_picture ? store.loggedUser.profile_picture : defaultProfilePicture} 
                        className="profile-picture" 
                        alt="Profile"
                        />
                    <h1 className="profile-name">{store.loggedUser.full_name}</h1>
                    <button type="button" className="btn btn-light ms-2" onClick={() => navigate('/editMyProfile')}>
                        <i className="fa-solid fa-gear"></i>
                    </button>
                </div>

                <div className="profile-section mb-4">
                    <h3>Profile Summary</h3>
                    <p>{store.loggedUser.profile_resume}</p>
                </div>

                <div className="profile-section mb-4">
                    <h3>Personal Information</h3>
                    <p>Birth date: {store.loggedUser.date_of_birth}</p>
                    <p>Gender: {store.loggedUser.gender}</p>
                </div>

                {store.loggedUser.role === 'vendor' && (
                    <div className="profile-section mb-4">
                        <h3>Offer Knowledge</h3>
                        <div className="dropdown">
                            <button className="btn btn-success dropdown-toggle" type="button" data-bs-toggle="dropdown" aria-expanded="false">
                                I can offer to you...
                            </button>
                            <ul className="dropdown-menu dropdown-knowledge">
                                {userKnowledge.map((filteredKnowledge, index) => {
                                    return(
                                        <li className="dropdown-item" key={index}>{filteredKnowledge.knowledge.description}</li>
                                    )                                    
                                })}
                            </ul>
                        </div>
                    </div>
                )}

                <div className="profile-section mb-4">
                    <h3>Gallery</h3>
                    <button className="btn btn-primary mb-3" onClick={() => setShowPictureUpload(!showPictureUpload)}>
                            {showPictureUpload ? "Hide Upload Form" : "Upload Images to Gallery"}
                    </button>
                        {showPictureUpload && (
                            <div className="picture-upload-container mt-4">
                                <form onSubmit={handleImageSubmit} className="picture-upload-form">
                                    <input 
                                        type="file" 
                                        accept="image/*" 
                                        className="form-control mb-3" 
                                        onChange={handleImage}
                                        name="gallery_picture"
                                    />
                                        {galleryPicturePreview && (
                                            <div className="preview-container">
                                                <img src={galleryPicturePreview} alt="Selected" className="preview-image" />
                                            </div>
                                        )}
                                    <button type="submit" className="btn btn-primary my-3">Upload</button>
                                </form>
                            </div>
                        )}
                    <div className="row">
                        {userGallery.length > 0 && userGallery.slice(0, Math.min(userGallery.length, 6)).map((galleryPicture, index) => (
                            <div className="col-md-4 col-sm-6 mb-3" key={index}>
                                <div className="card h-100">
                                    <img src={galleryPicture.gallery_pictures} className="card-img-top gallery-img" alt={`Gallery ${index}`} />
                                    <div className="card-body">
                                        <h5 className="card-title">Gallery Image {index + 1}</h5>
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div> 
            }                       
        </div>   
    )
}