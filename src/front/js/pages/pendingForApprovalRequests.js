import React,{ useContext, useEffect, useState} from "react";
import { Context } from "../store/appContext";
import { useNavigate } from "react-router-dom";
import { getData } from "../utils/getData";
import "../../styles/home.css";

export const PendingForApprovalRequests = () =>{
    const {actions, store} = useContext(Context)
    const navigate = useNavigate()
    const [serviceRequestOffered, setServiceRequestOffered] = useState([])
    const [pendingdOffers, setPendingOffers] = useState([])
    const [offeredToMyUser, setOfferedToMyUser] = useState({})
    const [tempData, setTempData] = useState()
    const [status, setStatus] = useState({
        "service_request_status": "taken",
        "service_request_offer_status": "accepted"
    })

    async function sendData(indexes){
        const result = await actions.updateServicesRequestsOffers(indexes,status)
        if(result == 201){
            navigate('/requestsInProcess')
        }
    }

    useEffect( ()=>{
        getData(actions.getServicesRequestsOffers, setServiceRequestOffered);      
    },[actions])

    useEffect( ()=>{
        setPendingOffers(serviceRequestOffered.filter( offered => offered.status === 'pending'))
    },[serviceRequestOffered])

    useEffect( ()=>{
        const filterByUser = async() => {
            if(store.loggedUser){
                setOfferedToMyUser(pendingdOffers.filter( offered => offered.user_client_id.email === store.loggedUser.email))
            }
        }
        filterByUser()        
    },[pendingdOffers, store.loggedUser])

    return(
        <div className="container background-color">
            <div className="body m-5">
                <div className="text-center ">
                    <h1 className="">Offers you've received</h1>
                </div>
                <div className="list-group">
                    {offeredToMyUser && offeredToMyUser.length > 0 && offeredToMyUser.map( (offered, index)=>{
                        return(
                            <div className="list-group-item mb-3 border-color" key={index}>
                                <div className="d-flex justify-content-between">
                                    <h3 className="primary-text">{offered.service_request_id.description}</h3>
                                </div>
                                <h4 className="text-color">Tasker: {offered.user_vendor_id.full_name}</h4>                        
                                <h4 className="text-color">Rate: ${offered.rate}</h4> 
                                <div className="list-group-item-footer">
                                    <button 
                                    type="button" 
                                    className="btn btn-primary" 
                                    data-bs-toggle="modal" 
                                    data-bs-target="#requestOfferModal"
                                    onClick={ ()=>setTempData({
                                        "service_request_offer_id": offered.id, 
                                        "service_request_id": offered.service_request_id.id
                                    })}
                                    >
                                        Accept tasker
                                    </button>
                                    <button 
                                    type="button" 
                                    className="btn btn-primary mx-2" 
                                    onClick={ ()=>navigate(`/reviewProfile/${offered.user_vendor_id.id}`) } 
                                    >
                                        Review tasker
                                    </button>

                                    <div className="modal fade" id="requestOfferModal" tabIndex="-1" aria-labelledby="exampleModalLabel" 
                                        aria-hidden="true">
                                        <div className="modal-dialog">
                                            <div className="modal-content">
                                                <div className="modal-header">
                                                    <h1 className="modal-title fs-5">Are you sure to take this tasker?</h1>
                                                    <button 
                                                    type="button" 
                                                    className="btn-close" 
                                                    data-bs-dismiss="modal" 
                                                    aria-label="Close"
                                                    ></button>
                                                </div>                                          
                                                <div className="modal-footer">
                                                    <button type="button" className="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                                    <button type="submit" className="btn btn-primary btn-primary-custom" data-bs-dismiss="modal" 
                                                    onClick={ ()=>sendData(tempData) }>Accept tasker</button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        )
                    })}                                             
                </div>
            </div>
        </div>
    )
}