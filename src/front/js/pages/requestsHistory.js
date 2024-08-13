import React, { useContext, useEffect, useState } from "react";
import { Context } from "../store/appContext";
import { useNavigate } from "react-router-dom";
import { getData } from "../utils/getData";
import "../../styles/home.css";

export const RequestsHistory = () => {
    const {store, actions} = useContext(Context)
    const navigate = useNavigate()
    const [servicesRequests, setServicesRequests] = useState([])
    const [requestsByUser, setRequestsByUser] = useState([])    
    const [tempData, setTempData] = useState()

    const cancelRequest = async (filteredServiceRequestId) =>{
        const response = await actions.cancelServiceRequest(filteredServiceRequestId)
        if( response == 201){
            navigate('/requestHistory')
        }
    }

    useEffect( ()=>{
        getData(actions.getServicesRequests, setServicesRequests);
    },[actions, actions.getServicesRequests()])

    useEffect( ()=>{
        if(store.loggedUser){
            setRequestsByUser(servicesRequests.filter( serviceRequest => serviceRequest.user.email === store.loggedUser.email))
        }        
    },[servicesRequests, store.loggedUser])

    useEffect( ()=>{
        if(store.loggedUser && store.loggedUser.role === 'vendor'){
            navigate('/')
        }
    },[store.loggedUser])

    return(        
        <div className="container">
            {store.loggedUser &&
            <div className="body m-5">
                <div className="text-center ">
                    <h1 className="">Your requests</h1>
                </div>
                <div className="list-group">
                    <h3 className=" ">Active requests</h3>
                    {requestsByUser.map( (filteredServiceRequest, index)=>{
                        if(filteredServiceRequest.is_active == true && filteredServiceRequest.status === 'pending'){
                            return(                          
                                <div className="list-group-item mb-3" key={index}>
                                    <div className="d-flex justify-content-between">
                                        <h3 className=" ">{filteredServiceRequest.service_subcategory_id.description}</h3>
                                        <p className=" ">{filteredServiceRequest.address}</p>
                                    </div>                            
                                    <p className="">{filteredServiceRequest.description}</p>
                                    <p className="">{filteredServiceRequest.moving}</p>
                                    <p className="">{filteredServiceRequest.tools}</p>                                    
                                    <button 
                                    type="button" 
                                    className="btn btn-danger" 
                                    data-bs-toggle="modal" 
                                    data-bs-target="#requestOfferModal"
                                    onClick={ ()=>setTempData(filteredServiceRequest.id)}
                                    >
                                        Cancel request
                                    </button>

                                    <div className="modal fade" id="requestOfferModal" tabIndex="-1" aria-labelledby="exampleModalLabel" 
                                        aria-hidden="true">
                                        <div className="modal-dialog">
                                            <div className="modal-content">
                                                <div className="modal-header">
                                                    <h1 className="modal-title fs-5">Cancel this request?</h1>
                                                    <button 
                                                    type="button" 
                                                    className="btn-close" 
                                                    data-bs-dismiss="modal" 
                                                    aria-label="Close"
                                                    ></button>
                                                </div>                                          
                                                <div className="modal-footer">
                                                    <button type="button" className="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                                    <button type="submit" className="btn btn-danger" data-bs-dismiss="modal" 
                                                    onClick={ ()=>cancelRequest(tempData) }>Cancel request</button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>                            
                            )
                        }                        
                    })}                    
                </div>
                <div className="list-group mt-5">
                    <h3 className=" ">Previous requests</h3>
                    {requestsByUser.map( (filteredServiceRequest, index)=>{
                        if(filteredServiceRequest.is_active == false){
                            return(
                                <div className="list-group-item mb-3" key={index}>
                                    <div className="d-flex justify-content-between">
                                        <h3 className=" ">{filteredServiceRequest.service_subcategory_id.description}</h3>
                                        <p className=" ">{filteredServiceRequest.address}</p>
                                    </div>                            
                                    <p className="">{filteredServiceRequest.description}</p>
                                    <p className="">{filteredServiceRequest.moving}</p>
                                    <p className="">{filteredServiceRequest.tools}</p>
                                </div>
                            )
                        }
                    })}                    
                </div>
            </div>
            }
        </div>
    )
}