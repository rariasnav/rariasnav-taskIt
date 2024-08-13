import React, {useContext, useEffect, useState} from "react";
import { Context } from "../store/appContext";
import { useNavigate } from "react-router-dom";
import { getData } from "../utils/getData";
import "../../styles/home.css";

export const AvailableRequests = () =>{
    const {actions} = useContext(Context)
    const navigate = useNavigate()
    const [requests, setRequests] = useState([])   
    const [knowledge, setKnowledge] = useState([])    
    const [activePendingRequests, setActivePendingRequests] = useState([])      
    const [userKnowledge, setUserKnowledge] = useState([])
    const [filteredRequests, setFilteredRequests] = useState([])
    const [requestServiceOffer, setRequestServiceOffer] = useState({
        "status": "pending",
        "rate": " "
    })
    const [tempData, setTempData] = useState()    

    const sendData = async (data) =>{    
        const result = await actions.offerServiceRequest(data, requestServiceOffer)
        if( result==201 ){
            navigate("/takenRequests")
        }
    }

    const handleChange = (e) =>{
        setRequestServiceOffer({
            ...requestServiceOffer, [e.target.name]: e.target.value
        })
    }

    useEffect( ()=>{
        getData(actions.getServicesRequests, setRequests);        
    },[])

    useEffect( ()=>{
        getData(actions.getOfferKnowledge, setKnowledge); 
    },[])

    useEffect( ()=> {
		setActivePendingRequests(requests.filter( serviceRequest => serviceRequest.is_active === true && serviceRequest.status === 'pending'))
	}, [requests])

    useEffect( ()=> {
		setUserKnowledge(knowledge.map( (known)=> known.knowledge.description ))
	}, [knowledge])

    useEffect( ()=> {
        if(activePendingRequests.length > 0 && userKnowledge.length > 0){
            setFilteredRequests(activePendingRequests.filter( request => userKnowledge.includes(request.service_subcategory_id.description) ))
        }		
	}, [activePendingRequests, userKnowledge])

    return(
        <div className="container background-color">
            <div className="body my-5">
                <div className="text-center ">
                    <h1 className="primary-text">Offers you can take</h1>
                </div>
                <div className="list-group">
                    {filteredRequests.map( (filteredServiceRequest, index) => {
                        return(
                            <div className="list-group-item mb-3 border-color" key={index}>
                                <div className="d-flex justify-content-between">
                                    <h3 className="primary-text">{filteredServiceRequest.service_subcategory_id.description}</h3>
                                    <p className="text-color">{filteredServiceRequest.address}</p>
                                </div>
                                <h4 className="primary-text">From: {filteredServiceRequest.user.full_name}</h4> 
                                <p className="text-color">{filteredServiceRequest.description}</p>
                                <p className="text-color">{filteredServiceRequest.moving}</p>
                                <p className="text-color">{filteredServiceRequest.tools}</p>
                                <button type="button" className="btn btn-primary" data-bs-toggle="modal" data-bs-target="#requestOfferModal"
                                onClick={ ()=> setTempData({
                                    "service_request_id": filteredServiceRequest.id, 
                                    "client_email": filteredServiceRequest.user.email}
                                    )}>
                                    Take request
                                </button>

                                    <div className="modal fade" id="requestOfferModal" tabIndex="-1" aria-labelledby="exampleModalLabel" 
                                    aria-hidden="true">
                                        <div className="modal-dialog">
                                            <div className="modal-content">
                                                <div className="modal-header">
                                                    <h1 className="modal-title fs-5 primary-text">Make your offer for this task</h1>
                                                    <button type="button" className="btn-close" data-bs-dismiss="modal" 
                                                    aria-label="Close"></button>
                                                </div>
                                                <div className="modal-body">
                                                    <p className="modal-title fs-5t">In order to take the task, give your rate</p>
                                                    <div className="input-group mb-3">                                                        
                                                        <input 
                                                            type="number" 
                                                            className="form-control" 
                                                            placeholder="$0.00"
                                                            name="rate"                                                         
                                                            value={requestServiceOffer.rate} 
                                                            onChange={handleChange}
                                                        />
                                                    </div>
                                                </div>
                                                <div className="modal-footer">
                                                    <button type="button" className="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                                                    <button type="button" className="btn btn-primary btn-primary-custom" data-bs-dismiss="modal" 
                                                    onClick={ ()=>sendData(tempData) }>Take task</button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                            </div> 
                        );
                    })}                     
                </div>
            </div>
        </div>
    )
}