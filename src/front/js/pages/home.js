import React, { useContext, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Context } from "../store/appContext";
import { getData } from "../utils/getData";
import "../../styles/home.css";

export const Home = () => {
	const { store, actions } = useContext(Context);
	const navigate = useNavigate();
	const [query, setQuery] = useState("");
	const [users, setUsers] = useState([]);
	const [categories, setCategories] = useState([]);
	const [subcategories, setSubcategories] = useState([]);
	const [displaySubcategories, setDisplaySubcategories] = useState([]);
	
	const getRandomSubcategory = (array, num) =>{
		const shuffled = array.slice();
		for(let i = shuffled.length - 1; i > 0; i--){
			const j = Math.floor(Math.random() * (i + 1));
			[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]]
		}
		return shuffled.slice(0, num)
	}

	useEffect( ()=>{
        getData(actions.loadTestData, setUsers);     
    },[])

	useEffect( ()=>{
		getData(actions.getCategories, setCategories);       
    },[])

	useEffect( ()=>{
		getData(actions.getSubcategories, setSubcategories);  
    },[])

	useEffect( ()=>{
		const selectedSubcategories = getRandomSubcategory(subcategories, 9)
		setDisplaySubcategories(selectedSubcategories)
	},[subcategories])	

	useEffect( ()=> {
		setUsers(users.filter( (item) => item.name.toLowerCase().includes(query) ))
	}, [query] )

	return (
		<div className="Container my-5">
			<div className="jumbotron bg-background-light-color text-center py-5 mb-4">
				<div className="container my-5">
					<div className="position-relative p-5 text-center text-muted bg-body border border-dashed rounded-5">	
						<ul className="list-group">
							<input 
							className="form-control text-center list-group-item" 
							placeholder="What service are you looking for?" 
							type="search" name="search_bar" 
							onChange={ (e)=> setQuery(e.target.value.toLowerCase())}
							/>
							<li className="list-group-item"></li>	
						</ul>						
					</div>
				</div>
			</div>
			<div className="testDiv row-g3">
				{users.sort( ()=> Math.random() - 0.5 ).map( (user, index)=> {
					return(
						<div className="col-md-4 col-sm-6" key={index}>
							<div className="card h-100 border-primary">
								<div className="card-body">
									<h5 className="card-title">{user.name}</h5>
									<h6 className="card-subtitle mb-2 text-muted">{user.email}</h6>	
								</div>
							</div>
						</div>
					);
				})}				
			</div>

			<div className="button-group row m-5 text-center">
				{categories.map( (category, index)=> {
					return(
						<div className="col-md-3 col-sm-6 mb-3" key={index}>
							<button 
								className="btn btn-outline-primary w-100" 
								onClick={ ()=>navigate('/demo') }
								>
								<div className="button-icon mb-2">
									<i className={`fa ${category.icon}`}></i>
								</div>					
								<div className="button-body">
									<p className="card-title">{category.name}</p>						
								</div>
							</button>
						</div>						
					);
				})}			
			</div>

			<div className="album py-5 bg-background-light-color">
    			<div className="container">
					<div className="row row-cols-1 row-cols-sm-2 row-cols-md-3 g-3">
						{displaySubcategories.map( (subcategory, index)=> {
							return(
									<div className="col" key={index}>
										<div className="card shadow-sm">
											<img
												src={`https://via.placeholder.com/150`}
												className="bd-placeholder-img card-img-top"
												alt={`Thumbnail ${subcategory.name}`}
											/>
											<div className="card-body">
												<h3 className="card-text">{subcategory.name}</h3>
												<p className="card-text">{subcategory.description}</p>
												<div className="d-flex justify-content-between align-items-center">
													<div className="btn-group">
														<button 
														type="button" 
														className="btn btn-sm btn-outline-secondary" 
														onClick={ ()=>navigate('/postForAService/'+subcategory.id) }
														>
														Ask for this service
														</button>
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
	</div>		
	);
};
